#!/usr/bin/env python3
"""
smpp_server.py — Minimal SMPP 3.4 server that triggers NextGenSwitch Programmable Voice API on SUBMIT_SM
and sends SMPP Delivery Receipts (DLR) based on NextGenSwitch call status callbacks.

NextGenSwitch callback JSON assumed:
{
  "call_id": "sdfs324234",
  "create_time": "YYYY-mm-dd HH:MM:SS",
  "end_time": "YYYY-mm-dd HH:MM:SS" | "",
  "establihed_at": "YYYY-mm-dd HH:MM:SS" | "",
  "duration": 12,
  "status": "Disconnected",
  "status-code": 3
}

Features:
- SMPP: BIND_TX/RX/TRX, SUBMIT_SM, ENQUIRE_LINK, UNBIND
- Calls NextGenSwitch POST /api/v1/call on SUBMIT_SM using responseXml <Say>... </Say>
- SUBMIT_SM_RESP message_id = call_id (or local fallback if missing)
- HTTP callback listener (stdlib http.server) to receive NextGenSwitch statusCallback
- Sends DELIVER_SM (esm_class=0x04) final receipt based on status-code mapping
- Optional CSV logging
- Optional IP whitelist file (one IP or CIDR per line) enforced at BIND time
- Optional SQLite billing with per-user auth, credit balance, and per-SMS charging

Run:
  python3 smpp_server.py --listen 0.0.0.0:2775 --http-listen 0.0.0.0:8080 \
    --ngs-base-url http://NGS --ngs-auth-code CODE --ngs-auth-secret SECRET \
    --ngs-status-callback https://PUBLIC_DOMAIN/ngs/status \
    --ip-whitelist-file ./whitelist.txt --csv-log ./smpp.csv --db ./smpp.db

User management:
  python3 smpp_server.py --db ./smpp.db --manage add-user \
      --system-id alice --password secret --credit 100.0 --rate 0.05
  python3 smpp_server.py --db ./smpp.db --manage list-users
  python3 smpp_server.py --db ./smpp.db --manage topup --system-id alice --amount 50.0
  python3 smpp_server.py --db ./smpp.db --manage report [--system-id alice]
  python3 smpp_server.py --db ./smpp.db --manage passwd --system-id alice --password newpass
  python3 smpp_server.py --db ./smpp.db --manage set-active --system-id alice --active 0
  python3 smpp_server.py --db ./smpp.db --manage set-rate --system-id alice --rate 0.10
"""

import asyncio
import argparse
import hashlib
import json
import logging
import secrets
import sqlite3
import struct
import time
import re
import urllib.parse
import urllib.request
import urllib.error
import csv
import os
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Optional, Tuple, Dict, Any, List
from xml.sax.saxutils import escape as xml_escape


# ---------------------------
# SMPP 3.4 Constants
# ---------------------------
BIND_RECEIVER            = 0x00000001
BIND_TRANSMITTER         = 0x00000002
SUBMIT_SM                = 0x00000004
DELIVER_SM               = 0x00000005
UNBIND                   = 0x00000006
BIND_TRANSCEIVER         = 0x00000009
ENQUIRE_LINK             = 0x00000015

BIND_RECEIVER_RESP       = 0x80000001
BIND_TRANSMITTER_RESP    = 0x80000002
SUBMIT_SM_RESP           = 0x80000004
DELIVER_SM_RESP          = 0x80000005
UNBIND_RESP              = 0x80000006
BIND_TRANSCEIVER_RESP    = 0x80000009
ENQUIRE_LINK_RESP        = 0x80000015

ESME_ROK                 = 0x00000000
ESME_RBINDFAIL           = 0x0000000D
ESME_RINVPASWD           = 0x0000000E
ESME_RSUBMITFAIL         = 0x00000045

SMPP_HDR_FMT = ">IIII"
SMPP_HDR_LEN = 16


# ---------------------------
# Helpers: C-Octet Strings
# ---------------------------
def read_cstring(buf: bytes, offset: int) -> Tuple[str, int]:
    end = buf.find(b"\x00", offset)
    if end == -1:
        return "", len(buf)
    s = buf[offset:end].decode("utf-8", errors="replace")
    return s, end + 1


def pack_cstring(s: str) -> bytes:
    return s.encode("utf-8", errors="replace") + b"\x00"


def unpack_header(pdu: bytes) -> Tuple[int, int, int, int]:
    if len(pdu) < SMPP_HDR_LEN:
        raise ValueError("PDU too short")
    return struct.unpack(SMPP_HDR_FMT, pdu[:SMPP_HDR_LEN])


def build_pdu(command_id: int, command_status: int, sequence_number: int, body: bytes = b"") -> bytes:
    command_length = SMPP_HDR_LEN + len(body)
    hdr = struct.pack(SMPP_HDR_FMT, command_length, command_id, command_status, sequence_number)
    return hdr + body


# ---------------------------
# Minimal PDU parsing
# ---------------------------
def parse_bind_body(body: bytes) -> Tuple[str, str, str, int]:
    off = 0
    system_id, off = read_cstring(body, off)
    password, off = read_cstring(body, off)
    system_type, off = read_cstring(body, off)
    interface_version = body[off] if off < len(body) else 0
    return system_id, password, system_type, interface_version


def parse_submit_sm_body(body: bytes) -> Tuple[str, str, str, int, int]:
    off = 0
    _, off = read_cstring(body, off)          # service_type

    off += 1                                  # source_addr_ton
    off += 1                                  # source_addr_npi
    source_addr, off = read_cstring(body, off)

    off += 1                                  # dest_addr_ton
    off += 1                                  # dest_addr_npi
    destination_addr, off = read_cstring(body, off)

    off += 1                                  # esm_class
    off += 1                                  # protocol_id
    off += 1                                  # priority_flag

    _, off = read_cstring(body, off)          # schedule_delivery_time
    _, off = read_cstring(body, off)          # validity_period

    registered_delivery = body[off] if off < len(body) else 0
    off += 1
    off += 1                                  # replace_if_present_flag

    data_coding = body[off] if off < len(body) else 0
    off += 1
    off += 1                                  # sm_default_msg_id

    if off >= len(body):
        return source_addr, destination_addr, "", registered_delivery, data_coding

    sm_length = body[off]
    off += 1
    short_message = body[off:off + sm_length].decode("utf-8", errors="replace")
    return source_addr, destination_addr, short_message, registered_delivery, data_coding


# ---------------------------
# IP Whitelist (optional)
# ---------------------------
class IpWhitelist:
    """
    Loads allowed IPs/CIDRs from a text file.
    Format: one entry per line:
      203.0.113.10
      203.0.113.0/24
      # comments allowed
    Hot-reloads when file mtime changes.
    """
    def __init__(self, path: str):
        self.path = path
        self._nets: List[ipaddress._BaseNetwork] = []
        self._mtime = 0.0
        self._load(force=True)

    def _load(self, force: bool = False):
        st = os.stat(self.path)
        if (not force) and st.st_mtime <= self._mtime:
            return

        self._mtime = st.st_mtime
        nets: List[ipaddress._BaseNetwork] = []

        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "/" not in line:
                    line = f"{line}/32"
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    logging.warning("Invalid whitelist entry ignored: %r", line)

        self._nets = nets
        logging.info("Loaded %d whitelist CIDRs from %s", len(self._nets), self.path)

    def reload_if_needed(self):
        try:
            self._load(force=False)
        except Exception as e:
            logging.error("Whitelist reload failed (%s): %s", self.path, e)

    def is_allowed(self, ip: str) -> bool:
        self.reload_if_needed()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._nets)


# ---------------------------
# CSV logging (optional)
# ---------------------------
class CsvAsyncLogger:
    FIELDNAMES = [
        "ts", "event", "peer", "peer_ip", "system_id", "bind_type", "smpp_seq",
        "src", "dst", "message",
        "ngs_ok", "ngs_http", "call_id",
        "call_status", "call_status_code", "note"
    ]

    def __init__(self, filepath: str, flush_every: int = 1):
        self.filepath = Path(filepath)
        self.flush_every = max(1, int(flush_every))
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=20000)
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    @staticmethod
    def _utc_ts() -> str:
        return datetime.now(timezone.utc).isoformat()

    async def start(self):
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._writer_loop())

    async def stop(self):
        if self._task is None:
            return
        self._stopping = True
        await self.queue.put(None)
        await self._task
        self._task = None

    def log(self, **row):
        if self._stopping:
            return
        base = {k: "" for k in self.FIELDNAMES}
        base["ts"] = self._utc_ts()
        for k, v in row.items():
            if k in base:
                base[k] = str(v)
        try:
            self.queue.put_nowait(base)
        except asyncio.QueueFull:
            logging.warning("CSV log queue full; dropping event=%s peer=%s", base.get("event"), base.get("peer"))

    async def _writer_loop(self):
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        file_exists = self.filepath.exists()

        f = open(self.filepath, "a", newline="", encoding="utf-8")
        w = csv.DictWriter(f, fieldnames=self.FIELDNAMES)

        if not file_exists:
            w.writeheader()
            f.flush()

        n = 0
        try:
            while True:
                item = await self.queue.get()
                if item is None:
                    break
                w.writerow(item)
                n += 1
                if n % self.flush_every == 0:
                    f.flush()
        except Exception:
            logging.exception("CSV writer loop error")
        finally:
            try:
                f.flush()
                f.close()
            except Exception:
                pass


# ---------------------------
# Password helpers (PBKDF2-SHA256, stdlib only)
# ---------------------------
def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 260000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


def _verify_password(stored: str, password: str) -> bool:
    try:
        parts = stored.split(":", 3)
        if len(parts) != 4 or parts[0] != "pbkdf2":
            return False
        _, algo, salt, dk_hex = parts
        dk = hashlib.pbkdf2_hmac(algo, password.encode("utf-8"), salt.encode("utf-8"), 260000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ---------------------------
# Database Manager (SQLite billing + auth)
# ---------------------------
class DatabaseManager:
    """
    SQLite-backed user auth and billing.
    All blocking calls go through asyncio.to_thread so the event loop never stalls.

    Tables:
      users          — credentials, credit balance, rate per SMS
      sessions       — one row per SMPP BIND, closed on disconnect
      messages       — one row per SUBMIT_SM with charge and DLR outcome
      billing_ledger — append-only ledger: every charge / topup with balance_after
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS users (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        system_id        TEXT    NOT NULL UNIQUE,
        password_hash    TEXT    NOT NULL,
        is_active        INTEGER NOT NULL DEFAULT 1,
        credit_balance   REAL    NOT NULL DEFAULT 0.0,
        rate_per_sms     REAL    NOT NULL DEFAULT 0.0,
        created_at       TEXT    NOT NULL,
        notes            TEXT    NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id          INTEGER NOT NULL REFERENCES users(id),
        peer             TEXT    NOT NULL DEFAULT '',
        peer_ip          TEXT    NOT NULL DEFAULT '',
        bind_mode        TEXT    NOT NULL DEFAULT '',
        session_start    TEXT    NOT NULL,
        session_end      TEXT    DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id          INTEGER NOT NULL REFERENCES users(id),
        session_id       INTEGER NOT NULL REFERENCES sessions(id),
        submit_ts        TEXT    NOT NULL,
        src              TEXT    NOT NULL DEFAULT '',
        dst              TEXT    NOT NULL DEFAULT '',
        message          TEXT    NOT NULL DEFAULT '',
        call_id          TEXT    NOT NULL DEFAULT '',
        ngs_ok           INTEGER NOT NULL DEFAULT 0,
        ngs_http         TEXT    NOT NULL DEFAULT '',
        smpp_seq         INTEGER NOT NULL DEFAULT 0,
        charge           REAL    NOT NULL DEFAULT 0.0,
        dlr_stat         TEXT    DEFAULT NULL,
        dlr_ts           TEXT    DEFAULT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_call_id ON messages(call_id);
    CREATE INDEX IF NOT EXISTS idx_messages_user_id  ON messages(user_id);

    CREATE TABLE IF NOT EXISTS billing_ledger (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id          INTEGER NOT NULL REFERENCES users(id),
        ts               TEXT    NOT NULL,
        type             TEXT    NOT NULL,
        amount           REAL    NOT NULL,
        balance_after    REAL    NOT NULL,
        message_id       INTEGER DEFAULT NULL REFERENCES messages(id),
        note             TEXT    NOT NULL DEFAULT ''
    );
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def _conn_(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ---- Schema ----

    def init_schema_sync(self):
        conn = self._conn_()
        conn.executescript(self._SCHEMA)
        conn.commit()

    async def init_schema(self):
        await asyncio.to_thread(self.init_schema_sync)

    # ---- Auth ----

    def _authenticate_sync(self, system_id: str, password: str) -> Optional[Dict[str, Any]]:
        conn = self._conn_()
        row = conn.execute("SELECT * FROM users WHERE system_id = ?", (system_id,)).fetchone()
        if row is None or not row["is_active"]:
            return None
        if not _verify_password(row["password_hash"], password):
            return None
        return dict(row)

    async def authenticate(self, system_id: str, password: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._authenticate_sync, system_id, password)

    # ---- Balance ----

    def _get_balance_sync(self, user_id: int) -> float:
        row = self._conn_().execute(
            "SELECT credit_balance FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return float(row["credit_balance"]) if row else 0.0

    async def get_balance(self, user_id: int) -> float:
        return await asyncio.to_thread(self._get_balance_sync, user_id)

    # ---- Sessions ----

    def _open_session_sync(self, user_id: int, peer: str, peer_ip: str, bind_mode: str) -> int:
        conn = self._conn_()
        cur = conn.execute(
            "INSERT INTO sessions (user_id, peer, peer_ip, bind_mode, session_start) VALUES (?, ?, ?, ?, ?)",
            (user_id, peer, peer_ip, bind_mode, self._utc_now())
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    async def open_session(self, user_id: int, peer: str, peer_ip: str, bind_mode: str) -> int:
        return await asyncio.to_thread(self._open_session_sync, user_id, peer, peer_ip, bind_mode)

    def _close_session_sync(self, session_id: int):
        conn = self._conn_()
        conn.execute("UPDATE sessions SET session_end = ? WHERE id = ?", (self._utc_now(), session_id))
        conn.commit()

    async def close_session(self, session_id: int):
        await asyncio.to_thread(self._close_session_sync, session_id)

    # ---- Messages + Billing ----

    def _record_and_charge_sync(
        self, user_id: int, session_id: int, src: str, dst: str,
        message: str, call_id: str, ngs_ok: bool, ngs_http: str,
        smpp_seq: int, charge: float
    ) -> Tuple[int, bool]:
        """
        Inserts a message row, then atomically deducts credit if charge > 0.
        Returns (message_id, charged_ok). charged_ok=False means insufficient balance.
        """
        conn = self._conn_()
        now = self._utc_now()
        cur = conn.execute(
            """INSERT INTO messages
               (user_id, session_id, submit_ts, src, dst, message, call_id,
                ngs_ok, ngs_http, smpp_seq, charge)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, session_id, now, src, dst, message, call_id,
             int(ngs_ok), ngs_http, smpp_seq, charge)
        )
        message_id = cur.lastrowid

        charged_ok = True
        if charge > 0:
            # Single SQL: only deducts when balance is sufficient — no race condition
            updated = conn.execute(
                "UPDATE users SET credit_balance = credit_balance - ? "
                "WHERE id = ? AND credit_balance >= ?",
                (charge, user_id, charge)
            ).rowcount

            if updated:
                new_bal = conn.execute(
                    "SELECT credit_balance FROM users WHERE id = ?", (user_id,)
                ).fetchone()["credit_balance"]
                conn.execute(
                    """INSERT INTO billing_ledger
                       (user_id, ts, type, amount, balance_after, message_id, note)
                       VALUES (?, ?, 'charge', ?, ?, ?, ?)""",
                    (user_id, now, charge, new_bal, message_id, f"call_id={call_id}")
                )
            else:
                charged_ok = False

        conn.commit()
        return message_id, charged_ok  # type: ignore[return-value]

    async def record_and_charge(
        self, user_id: int, session_id: int, src: str, dst: str,
        message: str, call_id: str, ngs_ok: bool, ngs_http: str,
        smpp_seq: int, charge: float
    ) -> Tuple[int, bool]:
        return await asyncio.to_thread(
            self._record_and_charge_sync,
            user_id, session_id, src, dst, message,
            call_id, ngs_ok, ngs_http, smpp_seq, charge
        )

    def _update_dlr_sync(self, call_id: str, stat: str):
        conn = self._conn_()
        conn.execute(
            "UPDATE messages SET dlr_stat = ?, dlr_ts = ? WHERE call_id = ?",
            (stat, self._utc_now(), call_id)
        )
        conn.commit()

    async def update_dlr(self, call_id: str, stat: str):
        await asyncio.to_thread(self._update_dlr_sync, call_id, stat)

    # ---- Management (sync — used from CLI, not from async context) ----

    def add_user_sync(self, system_id: str, password: str, credit: float, rate: float, notes: str = "") -> None:
        conn = self._conn_()
        now = self._utc_now()
        conn.execute(
            """INSERT INTO users (system_id, password_hash, is_active, credit_balance, rate_per_sms, created_at, notes)
               VALUES (?, ?, 1, ?, ?, ?, ?)""",
            (system_id, _hash_password(password), credit, rate, now, notes)
        )
        if credit > 0:
            uid = conn.execute("SELECT id FROM users WHERE system_id = ?", (system_id,)).fetchone()["id"]
            conn.execute(
                """INSERT INTO billing_ledger (user_id, ts, type, amount, balance_after, note)
                   VALUES (?, ?, 'topup', ?, ?, 'initial credit')""",
                (uid, now, credit, credit)
            )
        conn.commit()

    def topup_sync(self, system_id: str, amount: float, note: str = "") -> float:
        conn = self._conn_()
        conn.execute(
            "UPDATE users SET credit_balance = credit_balance + ? WHERE system_id = ?",
            (amount, system_id)
        )
        row = conn.execute(
            "SELECT id, credit_balance FROM users WHERE system_id = ?", (system_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"User not found: {system_id!r}")
        conn.execute(
            """INSERT INTO billing_ledger (user_id, ts, type, amount, balance_after, note)
               VALUES (?, ?, 'topup', ?, ?, ?)""",
            (row["id"], self._utc_now(), amount, row["credit_balance"], note or "manual topup")
        )
        conn.commit()
        return float(row["credit_balance"])

    def list_users_sync(self) -> List[Dict[str, Any]]:
        rows = self._conn_().execute(
            "SELECT id, system_id, is_active, credit_balance, rate_per_sms, created_at, notes "
            "FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    def report_sync(self, system_id: Optional[str] = None) -> Dict[str, Any]:
        conn = self._conn_()
        if system_id:
            user = conn.execute("SELECT * FROM users WHERE system_id = ?", (system_id,)).fetchone()
            if not user:
                return {"error": f"User not found: {system_id!r}"}
            uid = user["id"]
            msgs = conn.execute(
                "SELECT COUNT(*) as total, COALESCE(SUM(charge),0) as spent, "
                "SUM(CASE WHEN ngs_ok=1 THEN 1 ELSE 0 END) as ok_calls "
                "FROM messages WHERE user_id = ?", (uid,)
            ).fetchone()
            ledger = conn.execute(
                "SELECT * FROM billing_ledger WHERE user_id = ? ORDER BY id DESC LIMIT 20", (uid,)
            ).fetchall()
            return {
                "user": dict(user),
                "messages": dict(msgs),
                "ledger_last20": [dict(r) for r in ledger],
            }
        rows = conn.execute(
            """SELECT u.system_id, u.credit_balance, u.is_active,
                      COUNT(m.id) as total_msgs, COALESCE(SUM(m.charge),0) as total_spent
               FROM users u LEFT JOIN messages m ON m.user_id = u.id
               GROUP BY u.id ORDER BY u.id"""
        ).fetchall()
        return {"users": [dict(r) for r in rows]}

    def set_active_sync(self, system_id: str, active: bool) -> None:
        conn = self._conn_()
        conn.execute("UPDATE users SET is_active = ? WHERE system_id = ?", (int(active), system_id))
        conn.commit()

    def set_rate_sync(self, system_id: str, rate: float) -> None:
        conn = self._conn_()
        conn.execute("UPDATE users SET rate_per_sms = ? WHERE system_id = ?", (rate, system_id))
        conn.commit()

    def passwd_sync(self, system_id: str, password: str) -> None:
        conn = self._conn_()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE system_id = ?",
            (_hash_password(password), system_id)
        )
        conn.commit()

    def close(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


# ---------------------------
# Connection State
# ---------------------------
@dataclass
class ConnState:
    peer: str
    peer_ip: str
    bound: bool = False
    system_id: str = ""
    bind_mode: str = ""        # "TX" / "RX" / "TRX"
    out_seq: int = 1000
    last_seen: float = 0.0
    user_id: int = 0           # DB user id; 0 = no DB / unauthenticated
    session_id: int = 0        # DB sessions.id; 0 = no open session
    rate_per_sms: float = 0.0  # cached from users.rate_per_sms at bind time


# ---------------------------
# OTP / code formatting for TTS
# ---------------------------
def tts_format_codes(text: str) -> str:
    s = (text or "").replace("–", "-").replace("—", "-")

    def digits_dot_newline(digits: str) -> str:
        return "".join(f"{d}.\n" for d in digits)

    def repl_prefix(m: re.Match) -> str:
        prefix = m.group(1)
        dash = m.group(2) or ""
        digits = m.group(3)
        formatted = digits_dot_newline(digits)
        return f"{prefix} - {formatted}" if dash else f"{prefix} {formatted}"

    s = re.sub(r"\b([A-Z]{1,6})(-)?(\d{4,})\b", repl_prefix, s)
    s = re.sub(r"\b\d{4,}\b", lambda m: digits_dot_newline(m.group(0)), s)

    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = "\n".join(line.strip() for line in s.split("\n"))
    return s


# ---------------------------
# NextGenSwitch Voice API Client
# ---------------------------
class NextGenSwitchClient:
    def __init__(
        self,
        base_url: str,
        auth_code: str,
        auth_secret: str,
        timeout: float = 8.0,
        status_callback: Optional[str] = None,
        default_caller: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_code = auth_code
        self.auth_secret = auth_secret
        self.timeout = timeout
        self.status_callback = status_callback
        self.default_caller = default_caller

    def _call_create_url(self) -> str:
        return f"{self.base_url}/api/v1/call"

    def build_say_xml(self, text: str, loop: int = 1) -> str:
        safe = xml_escape(text)
        return f'<?xml version="1.0" encoding="UTF-8"?><Response><Say loop="{loop}">{safe}</Say></Response>'

    def post_call_play_sms(self, to_number: str, from_number: str, message: str) -> Tuple[bool, str, str]:
        """
        POST /api/v1/call with form fields:
          to, from, responseXml (+ optional statusCallback)
        Returns (ok, call_id, http_status)
        """
        url = self._call_create_url()

        original_from = from_number
        if self.default_caller:
            from_number = self.default_caller

        spoken = tts_format_codes(message)
        logging.info("change spoken to %s", spoken)
        response_xml = self.build_say_xml(spoken, loop=2)

        form = {"to": to_number, "from": from_number, "responseXml": response_xml}
        if self.status_callback:
            form["statusCallback"] = self.status_callback

        data = urllib.parse.urlencode(form).encode("utf-8")
        req = urllib.request.Request(url=url, data=data, method="POST")
        req.add_header("X-Authorization", self.auth_code)
        req.add_header("X-Authorization-Secret", self.auth_secret)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        logging.info("[NGS] POST %s to=%r from=%r (orig_from=%r) statusCallback=%r",
                     url, to_number, from_number, original_from, self.status_callback)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                code = resp.getcode()
                raw = resp.read() or b""
                text = raw.decode("utf-8", errors="replace")
                logging.info("[NGS] HTTP %s body=%s", code,
                             text[:800] + ("...(trunc)" if len(text) > 800 else ""))

                if not (200 <= code < 300):
                    return False, "", str(code)

                call_id = ""
                try:
                    j = json.loads(text) if text.strip() else {}
                    call_id = str(j.get("call_id") or j.get("callId") or j.get("id") or "")
                except Exception:
                    call_id = ""

                return True, call_id, str(code)

        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            logging.error("[NGS] HTTPError %s %s body=%s",
                          getattr(e, "code", "?"), getattr(e, "reason", "?"),
                          err_body[:800] + ("...(trunc)" if len(err_body) > 800 else ""))
            return False, "", str(getattr(e, "code", ""))

        except urllib.error.URLError as e:
            logging.error("[NGS] URLError reason=%s", getattr(e, "reason", e))
            return False, "", ""

        except Exception as e:
            logging.exception("[NGS] Exception during POST: %s", e)
            return False, "", ""


# ---------------------------
# DLR mapping: NextGenSwitch status-code -> SMPP receipt
# ---------------------------
def map_ngs_status_code_to_smpp(status_code: int) -> Tuple[str, str, bool]:
    """Returns (stat, err, is_final)"""
    if status_code in (-1, 0, 1):
        return ("ENROUTE", "000", False)
    if status_code == 2:
        return ("ACCEPTD", "000", False)
    if status_code == 3:   # Disconnected (success)
        return ("DELIVRD", "000", True)
    if status_code == 4:   # Busy
        return ("UNDELIV", "004", True)
    if status_code == 5:   # NoAnswer
        return ("UNDELIV", "005", True)
    if status_code == 6:   # Cancelled
        return ("REJECTD", "006", True)
    if status_code == 7:   # Failed
        return ("UNDELIV", "007", True)
    return ("UNKNOWN", "000", False)


def _fmt_smpp_time(t: float) -> str:
    return time.strftime("%y%m%d%H%M", time.gmtime(t))


def make_dlr_text(message_id: str, stat: str, submit_ts: float, done_ts: float, err: str, orig_text: str = "") -> str:
    text20 = (orig_text or "")[:20].replace("\n", " ").replace("\r", " ")
    dlvrd = "001" if stat == "DELIVRD" else "000"
    return (
        f"id:{message_id} sub:001 dlvrd:{dlvrd} "
        f"submit date:{_fmt_smpp_time(submit_ts)} done date:{_fmt_smpp_time(done_ts)} "
        f"stat:{stat} err:{err} text:{text20}"
    )


def build_deliver_sm(seq: int, src_addr: str, dst_addr: str, dlr_text: str, data_coding: int = 0x00) -> bytes:
    """Builds DELIVER_SM with esm_class=0x04 (delivery receipt)."""
    sm_bytes = dlr_text.encode("utf-8", errors="replace")[:255]
    body = (
        b"\x00" +                                                          # service_type
        bytes([0x00, 0x00]) + pack_cstring(src_addr) +                    # src ton/npi/addr
        bytes([0x00, 0x00]) + pack_cstring(dst_addr) +                    # dst ton/npi/addr
        bytes([0x04, 0x00, 0x00]) +                                       # esm_class, protocol_id, priority_flag
        b"\x00" + b"\x00" +                                               # schedule_delivery_time, validity_period
        bytes([0x00, 0x00, data_coding & 0xFF, 0x00]) +                   # reg_del, replace, data_coding, msg_id
        bytes([len(sm_bytes)]) + sm_bytes
    )
    return build_pdu(DELIVER_SM, ESME_ROK, seq, body)


# ---------------------------
# HTTP callback server (stdlib, thread)
# ---------------------------
class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class _CallbackHandler(BaseHTTPRequestHandler):
    loop: asyncio.AbstractEventLoop = None  # type: ignore
    smpp_server: "SmppServer" = None        # type: ignore
    path_expected: str = "/ngs/status"      # type: ignore

    def do_POST(self):
        if self.path != self.path_expected:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""

        try:
            data = json.loads(body.decode("utf-8", errors="replace")) if body else {}
        except Exception:
            data = {}

        try:
            asyncio.run_coroutine_threadsafe(
                self.smpp_server.handle_ngs_callback(data),
                self.loop
            )
        except Exception:
            logging.exception("Error scheduling callback handler")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        logging.debug("[HTTP] " + fmt, *args)


def start_callback_http_server(loop: asyncio.AbstractEventLoop, smpp_server: "SmppServer",
                               host: str, port: int, path: str) -> Thread:
    _CallbackHandler.loop = loop
    _CallbackHandler.smpp_server = smpp_server
    _CallbackHandler.path_expected = path

    httpd = _ThreadingHTTPServer((host, port), _CallbackHandler)

    def _run():
        logging.info("HTTP callback server listening on http://%s:%d%s", host, port, path)
        httpd.serve_forever(poll_interval=0.5)

    t = Thread(target=_run, daemon=True)
    t.start()
    smpp_server._httpd = httpd  # type: ignore
    return t


# ---------------------------
# SMPP Server
# ---------------------------
class SmppServer:
    def __init__(
        self,
        accept_any_password: bool = True,
        fixed_password: Optional[str] = None,
        ngs: Optional[NextGenSwitchClient] = None,
        csv_logger: Optional[CsvAsyncLogger] = None,
        ip_whitelist: Optional[IpWhitelist] = None,
        dlr_intermediate: bool = False,
        db: Optional[DatabaseManager] = None,
    ):
        self.accept_any_password = accept_any_password
        self.fixed_password = fixed_password
        self.ngs = ngs
        self.csv = csv_logger
        self.ip_whitelist = ip_whitelist
        self.dlr_intermediate = dlr_intermediate
        self.db = db

        self._lock = asyncio.Lock()
        self._connections: Dict[asyncio.StreamWriter, ConnState] = {}
        self._rx_sessions: Dict[str, set] = {}   # system_id -> set(writers)
        self._call_map: Dict[str, Dict[str, Any]] = {}
        self._httpd = None

    def _validate_password_fallback(self, system_id: str, password: str) -> bool:
        if self.accept_any_password:
            return True
        if self.fixed_password is None:
            return False
        return password == self.fixed_password

    def _bind_resp_id(self, bind_cmd_id: int) -> int:
        if bind_cmd_id == BIND_TRANSMITTER:
            return BIND_TRANSMITTER_RESP
        if bind_cmd_id == BIND_RECEIVER:
            return BIND_RECEIVER_RESP
        return BIND_TRANSCEIVER_RESP

    def _bind_mode(self, bind_cmd_id: int) -> str:
        if bind_cmd_id == BIND_TRANSMITTER:
            return "TX"
        if bind_cmd_id == BIND_RECEIVER:
            return "RX"
        return "TRX"

    async def _ngs_call_in_thread(self, to_number: str, from_number: str, message: str) -> Tuple[bool, str, str]:
        if not self.ngs:
            return True, "", ""
        try:
            return await asyncio.to_thread(self.ngs.post_call_play_sms, to_number, from_number, message)
        except AttributeError:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.ngs.post_call_play_sms, to_number, from_number, message)

    async def _register_connection(self, writer: asyncio.StreamWriter, st: ConnState):
        async with self._lock:
            self._connections[writer] = st
            if st.bound and st.bind_mode in ("RX", "TRX") and st.system_id:
                self._rx_sessions.setdefault(st.system_id, set()).add(writer)

    async def _unregister_connection(self, writer: asyncio.StreamWriter):
        async with self._lock:
            st = self._connections.pop(writer, None)
            if st and st.system_id:
                writers = self._rx_sessions.get(st.system_id)
                if writers and writer in writers:
                    writers.remove(writer)
                    if not writers:
                        self._rx_sessions.pop(st.system_id, None)

    async def _send_pdu_safe(self, writer: asyncio.StreamWriter, pdu: bytes) -> bool:
        try:
            writer.write(pdu)
            await writer.drain()
            return True
        except Exception:
            await self._unregister_connection(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return False

    async def handle_ngs_callback(self, data: Dict[str, Any]):
        call_id = str(data.get("call_id") or "")
        status_text = str(data.get("status") or "")
        status_code_raw = data.get("status-code")

        if not call_id:
            logging.warning("[CB] Missing call_id in callback: %r", data)
            return

        try:
            status_code = int(status_code_raw)
        except Exception:
            status_code = 0

        stat, err, is_final = map_ngs_status_code_to_smpp(status_code)

        logging.info("[CB] call_id=%s status=%s status-code=%s -> stat=%s final=%s",
                     call_id, status_text, status_code, stat, is_final)

        if self.csv:
            self.csv.log(event="ngs_callback", call_id=call_id,
                         call_status=status_text, call_status_code=status_code, note="received")

        async with self._lock:
            info = self._call_map.get(call_id)
            if not info:
                if self.csv:
                    self.csv.log(event="dlr_skip", call_id=call_id, note="unknown call_id")
                return

            if self.dlr_intermediate and status_code == 2:
                if info.get("dlr_requested") and not info.get("acceptd_sent"):
                    info["acceptd_sent"] = True
                    snapshot = dict(info)
                else:
                    return
            else:
                snapshot = None

            if not is_final:
                if snapshot is None:
                    return

            if is_final:
                if info.get("final_sent"):
                    return
                info["final_sent"] = True
                snapshot_final = dict(info)
            else:
                snapshot_final = None

        if snapshot is not None:
            await self._send_dlr(call_id=call_id, info=snapshot, stat="ACCEPTD", err="000")

        if snapshot_final is not None:
            await self._send_dlr(call_id=call_id, info=snapshot_final, stat=stat, err=err)

        if is_final and self.db:
            await self.db.update_dlr(call_id, stat)

    async def _send_dlr(self, call_id: str, info: Dict[str, Any], stat: str, err: str):
        if not info.get("dlr_requested"):
            if self.csv:
                self.csv.log(event="dlr_skip", call_id=call_id, note="registered_delivery not requested")
            return

        system_id = str(info.get("system_id") or "")
        submit_ts = float(info.get("submit_ts") or time.time())
        done_ts = time.time()
        orig_text = str(info.get("text") or "")
        src = str(info.get("src") or "")
        dst = str(info.get("dst") or "")
        data_coding = int(info.get("data_coding") or 0)

        dlr_text = make_dlr_text(call_id, stat, submit_ts, done_ts, err, orig_text)

        async with self._lock:
            writers = list(self._rx_sessions.get(system_id, set()))
            conn_states = {w: self._connections.get(w) for w in writers}

        if not writers:
            logging.warning("[DLR] No RX/TRX session for system_id=%r call_id=%r", system_id, call_id)
            if self.csv:
                self.csv.log(event="dlr_fail", system_id=system_id, call_id=call_id, note="no rx sessions")
            return

        for w in writers:
            st = conn_states.get(w)
            if not st:
                continue
            seq = st.out_seq
            st.out_seq += 1

            pdu = build_deliver_sm(seq, src_addr=dst, dst_addr=src, dlr_text=dlr_text, data_coding=data_coding)
            ok = await self._send_pdu_safe(w, pdu)

            logging.info("[DLR] send to system_id=%s peer=%s call_id=%s stat=%s err=%s ok=%s",
                         system_id, st.peer, call_id, stat, err, ok)

            if self.csv:
                self.csv.log(
                    event="dlr_send", peer=st.peer, peer_ip=st.peer_ip,
                    system_id=system_id, src=src, dst=dst, call_id=call_id,
                    call_status=stat, call_status_code=err, note=("ok" if ok else "fail")
                )

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else ""
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"

        st = ConnState(peer=peer_str, peer_ip=peer_ip, last_seen=time.time())
        await self._register_connection(writer, st)

        logging.info("connection established from %s", st.peer)
        if self.csv:
            self.csv.log(event="connect", peer=st.peer, peer_ip=st.peer_ip)

        try:
            while True:
                try:
                    len_bytes = await reader.readexactly(4)
                except asyncio.IncompleteReadError:
                    break

                (pdu_len,) = struct.unpack(">I", len_bytes)
                if pdu_len < SMPP_HDR_LEN or pdu_len > 1024 * 1024:
                    logging.warning("invalid pdu_len=%s from %s; closing", pdu_len, st.peer)
                    break

                rest = await reader.readexactly(pdu_len - 4)
                pdu = len_bytes + rest

                _, cmd_id, _, seq = unpack_header(pdu)
                body = pdu[SMPP_HDR_LEN:]

                if st.bound:
                    if cmd_id == SUBMIT_SM:
                        await self.on_submit_sm(st, body, seq, writer)
                    elif cmd_id == ENQUIRE_LINK:
                        resp = build_pdu(ENQUIRE_LINK_RESP, ESME_ROK, seq)
                        await self._send_pdu_safe(writer, resp)
                    elif cmd_id == UNBIND:
                        resp = build_pdu(UNBIND_RESP, ESME_ROK, seq)
                        await self._send_pdu_safe(writer, resp)
                        if self.csv:
                            self.csv.log(event="unbind", peer=st.peer, peer_ip=st.peer_ip,
                                         system_id=st.system_id, smpp_seq=seq)
                        break
                    elif cmd_id == DELIVER_SM_RESP:
                        logging.debug("deliver_sm_resp from %s seq=%s", st.peer, seq)
                    else:
                        logging.info("unsupported cmd_id=0x%08x from %s (bound)", cmd_id, st.peer)
                else:
                    await self.on_bind(st, cmd_id, body, seq, writer)

                st.last_seen = time.time()

        except Exception as e:
            logging.exception("error handling %s: %s", st.peer, e)
            if self.csv:
                self.csv.log(event="error", peer=st.peer, peer_ip=st.peer_ip,
                             system_id=st.system_id, note=str(e))
        finally:
            await self._unregister_connection(writer)
            if self.db and st.session_id:
                await self.db.close_session(st.session_id)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logging.info("connection closed from %s", st.peer)
            if self.csv:
                self.csv.log(event="disconnect", peer=st.peer, peer_ip=st.peer_ip, system_id=st.system_id)

    async def on_bind(self, st: ConnState, cmd_id: int, body: bytes, seq: int, writer: asyncio.StreamWriter):
        if cmd_id not in (BIND_TRANSMITTER, BIND_RECEIVER, BIND_TRANSCEIVER):
            logging.info("reject non-bind cmd_id=0x%08x from %s (not bound)", cmd_id, st.peer)
            return

        system_id, password, system_type, if_ver = parse_bind_body(body)
        resp_id = self._bind_resp_id(cmd_id)
        bind_mode = self._bind_mode(cmd_id)

        # IP whitelist check
        if self.ip_whitelist and not self.ip_whitelist.is_allowed(st.peer_ip):
            logging.warning("BIND rejected by IP whitelist: peer=%s ip=%s system_id=%r",
                            st.peer, st.peer_ip, system_id)
            await self._send_pdu_safe(writer, build_pdu(resp_id, ESME_RBINDFAIL, seq, pack_cstring("")))
            if self.csv:
                self.csv.log(event="ip_denied", peer=st.peer, peer_ip=st.peer_ip,
                             system_id=system_id, bind_type=bind_mode, smpp_seq=seq)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        # Auth: DB takes priority over legacy password
        db_user: Optional[Dict[str, Any]] = None
        if self.db:
            db_user = await self.db.authenticate(system_id, password)
            ok_pwd = db_user is not None
        else:
            ok_pwd = self._validate_password_fallback(system_id, password)

        status = ESME_ROK if ok_pwd else ESME_RINVPASWD
        resp_body = pack_cstring(system_id) if ok_pwd else pack_cstring("")
        await self._send_pdu_safe(writer, build_pdu(resp_id, status, seq, resp_body))

        st.bound = bool(ok_pwd)
        st.system_id = system_id
        st.bind_mode = bind_mode

        if ok_pwd and db_user:
            st.user_id = int(db_user["id"])
            st.rate_per_sms = float(db_user.get("rate_per_sms") or 0.0)
            st.session_id = await self.db.open_session(  # type: ignore[union-attr]
                st.user_id, st.peer, st.peer_ip, bind_mode
            )

        await self._register_connection(writer, st)

        logging.info("bind from %s ip=%s system_id=%r bind_mode=%s system_type=%r if_ver=0x%02x -> %s",
                     st.peer, st.peer_ip, system_id, bind_mode, system_type, if_ver,
                     "OK" if ok_pwd else f"FAIL (tried password={password!r})")

        if self.csv:
            self.csv.log(
                event="bind", peer=st.peer, peer_ip=st.peer_ip,
                system_id=system_id, bind_type=bind_mode, smpp_seq=seq,
                ngs_ok=ok_pwd, note=("OK" if ok_pwd else "FAIL")
            )

    async def on_submit_sm(self, st: ConnState, body: bytes, seq: int, writer: asyncio.StreamWriter):
        source, dest, msg, registered_delivery, data_coding = parse_submit_sm_body(body)
        dlr_requested = bool(registered_delivery & 0x01)

        logging.info("submit_sm from %s: from=%s to=%s reg_deliv=0x%02x msg=%r",
                     st.peer, source, dest, registered_delivery, msg)

        # Credit pre-flight check (DB mode only, when rate > 0)
        if self.db and st.user_id and st.rate_per_sms > 0:
            balance = await self.db.get_balance(st.user_id)
            if balance < st.rate_per_sms:
                logging.warning(
                    "submit_sm rejected: insufficient credit system_id=%s balance=%.4f rate=%.4f",
                    st.system_id, balance, st.rate_per_sms
                )
                if self.csv:
                    self.csv.log(
                        event="submit_sm_rejected", peer=st.peer, peer_ip=st.peer_ip,
                        system_id=st.system_id, smpp_seq=seq, src=source, dst=dest, message=msg,
                        note=f"no_credit balance={balance:.4f} rate={st.rate_per_sms:.4f}"
                    )
                await self._send_pdu_safe(writer, build_pdu(SUBMIT_SM_RESP, ESME_RSUBMITFAIL, seq, pack_cstring("")))
                return

        if self.csv:
            self.csv.log(
                event="submit_sm", peer=st.peer, peer_ip=st.peer_ip,
                system_id=st.system_id, smpp_seq=seq, src=source, dst=dest, message=msg,
                note=f"registered_delivery=0x{registered_delivery:02x}"
            )

        ok, call_id, http_status = await self._ngs_call_in_thread(to_number=dest, from_number=source, message=msg)

        message_id = call_id or f"local-{int(time.time()*1000)}-{seq}"

        # Record message and charge credit in DB
        if self.db and st.user_id and st.session_id:
            charge = st.rate_per_sms if ok else 0.0
            await self.db.record_and_charge(
                user_id=st.user_id, session_id=st.session_id,
                src=source, dst=dest, message=msg, call_id=message_id,
                ngs_ok=ok, ngs_http=http_status, smpp_seq=seq, charge=charge
            )

        # Store correlation for DLR delivery
        async with self._lock:
            info = {
                "system_id": st.system_id,
                "src": source, "dst": dest, "text": msg,
                "submit_ts": time.time(),
                "dlr_requested": dlr_requested,
                "data_coding": data_coding,
                "final_sent": False, "acceptd_sent": False,
                "http_status": http_status, "ngs_ok": ok,
            }
            self._call_map[message_id] = info
            if call_id and call_id != message_id:
                self._call_map[call_id] = info

        smpp_status = ESME_ROK if ok else ESME_RSUBMITFAIL
        await self._send_pdu_safe(writer, build_pdu(SUBMIT_SM_RESP, smpp_status, seq, pack_cstring(message_id)))

        logging.info("submit_sm_resp to %s: ok=%s status=0x%08x message_id=%r call_id=%r http=%r dlr_requested=%s",
                     st.peer, ok, smpp_status, message_id, call_id, http_status, dlr_requested)

        if self.csv:
            self.csv.log(
                event="submit_sm_resp", peer=st.peer, peer_ip=st.peer_ip,
                system_id=st.system_id, smpp_seq=seq, src=source, dst=dest,
                ngs_ok=ok, ngs_http=http_status, call_id=message_id,
                note=("ok" if ok else "fail")
            )


# ---------------------------
# .env loader
# ---------------------------
def _load_dotenv(path: Optional[str] = None) -> None:
    """
    Load KEY=VALUE pairs from .env into os.environ.
    Existing environment variables are never overwritten (env wins over .env).
    Looks for .env next to this script unless path is given.
    """
    dotenv_path = Path(path) if path else Path(__file__).with_name(".env")
    if not dotenv_path.exists():
        return
    with open(dotenv_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip optional surrounding quotes
            if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value


# ---------------------------
# Management CLI
# ---------------------------
def run_manage(args) -> int:
    if not args.db:
        print("ERROR: --db is required for --manage commands")
        return 1

    db = DatabaseManager(args.db)
    db.init_schema_sync()
    cmd = args.manage

    try:
        if cmd == "add-user":
            if not args.system_id or not args.password:
                print("ERROR: --system-id and --password are required")
                return 1
            db.add_user_sync(
                system_id=args.system_id,
                password=args.password,
                credit=args.credit or 0.0,
                rate=args.rate or 0.0,
                notes=args.notes or "",
            )
            print(f"User '{args.system_id}' created. credit={args.credit or 0.0:.4f} rate={args.rate or 0.0:.4f}")

        elif cmd == "list-users":
            users = db.list_users_sync()
            if not users:
                print("No users found.")
            else:
                print(f"{'ID':<5} {'system_id':<20} {'active':<7} {'balance':>12} {'rate':>10}  created_at")
                print("-" * 72)
                for u in users:
                    print(
                        f"{u['id']:<5} {u['system_id']:<20} "
                        f"{'yes' if u['is_active'] else 'no':<7} "
                        f"{u['credit_balance']:>12.4f} {u['rate_per_sms']:>10.4f}  "
                        f"{u['created_at'][:19]}"
                    )

        elif cmd == "topup":
            if not args.system_id or args.amount is None:
                print("ERROR: --system-id and --amount are required")
                return 1
            new_bal = db.topup_sync(args.system_id, args.amount)
            print(f"Topped up '{args.system_id}' by {args.amount:.4f}. New balance: {new_bal:.4f}")

        elif cmd == "report":
            r = db.report_sync(args.system_id)
            print(json.dumps(r, indent=2, default=str))

        elif cmd == "passwd":
            if not args.system_id or not args.password:
                print("ERROR: --system-id and --password are required")
                return 1
            db.passwd_sync(args.system_id, args.password)
            print(f"Password updated for '{args.system_id}'")

        elif cmd == "set-active":
            if not args.system_id or args.active is None:
                print("ERROR: --system-id and --active (0 or 1) are required")
                return 1
            active = bool(int(args.active))
            db.set_active_sync(args.system_id, active)
            print(f"User '{args.system_id}' active={'yes' if active else 'no'}")

        elif cmd == "set-rate":
            if not args.system_id or args.rate is None:
                print("ERROR: --system-id and --rate are required")
                return 1
            db.set_rate_sync(args.system_id, args.rate)
            print(f"User '{args.system_id}' rate set to {args.rate:.4f}")

        else:
            print(f"ERROR: Unknown manage command: {cmd!r}")
            print("Valid: add-user, list-users, topup, report, passwd, set-active, set-rate")
            return 1

    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        db.close()

    return 0


# ---------------------------
# Main
# ---------------------------
async def main():
    # Load .env first so its values become os.environ defaults below
    _load_dotenv()

    def _env(key: str, fallback: str = "") -> Optional[str]:
        v = os.environ.get(key, fallback)
        return v if v else None

    ap = argparse.ArgumentParser(
        description="SMPP server -> NextGenSwitch call-create + DLR + optional SQLite billing"
    )
    ap.add_argument("--listen",    default=os.environ.get("SMPP_LISTEN",  "0.0.0.0:2775"))
    ap.add_argument("--log-level", default=os.environ.get("LOG_LEVEL",    "INFO"))

    # Auth
    ap.add_argument("--password", default=_env("SMPP_PASSWORD"),
                    help="Legacy single SMPP bind password (ignored when --db is active). "
                         "Also used as --password for management commands.")

    # SQLite billing
    ap.add_argument("--db", default=_env("DB_PATH"),
                    help="Path to SQLite billing DB (e.g. ./smpp.db)")

    # Management mode
    ap.add_argument("--manage", default=None, metavar="CMD",
                    help="Run management command and exit: "
                         "add-user | list-users | topup | report | passwd | set-active | set-rate")
    ap.add_argument("--system-id", default=None, help="[manage] SMPP system_id / username")
    ap.add_argument("--credit", type=float, default=None, help="[manage add-user] Initial credit")
    ap.add_argument("--rate",   type=float, default=None, help="[manage] Rate per SMS/call")
    ap.add_argument("--amount", type=float, default=None, help="[manage topup] Amount to add")
    ap.add_argument("--active", default=None, help="[manage set-active] 1=active 0=disabled")
    ap.add_argument("--notes",  default=None, help="[manage add-user] Optional notes")

    # IP whitelist
    ap.add_argument("--ip-whitelist-file", default=_env("IP_WHITELIST_FILE"))

    # NextGenSwitch
    ap.add_argument("--ngs-base-url",        default=_env("NGS_BASE_URL"))
    ap.add_argument("--ngs-auth-code",       default=_env("NGS_AUTH_CODE"))
    ap.add_argument("--ngs-auth-secret",     default=_env("NGS_AUTH_SECRET"))
    ap.add_argument("--ngs-timeout",         type=float,
                    default=float(os.environ.get("NGS_TIMEOUT", "8.0")))
    ap.add_argument("--ngs-status-callback", default=_env("NGS_STATUS_CALLBACK"))
    ap.add_argument("--ngs-default-from",    default=_env("NGS_DEFAULT_FROM"))

    # HTTP callback listener
    ap.add_argument("--http-listen", default=os.environ.get("HTTP_LISTEN", "0.0.0.0:8080"))
    ap.add_argument("--http-path",   default=os.environ.get("HTTP_PATH",   "/ngs/status"))

    # DLR behavior
    _dlr_default = os.environ.get("DLR_INTERMEDIATE", "false").lower() == "true"
    ap.add_argument("--dlr-intermediate", action="store_true", default=_dlr_default)

    # CSV logging
    ap.add_argument("--csv-log",         default=_env("CSV_LOG"))
    ap.add_argument("--csv-flush-every", type=int,
                    default=int(os.environ.get("CSV_FLUSH_EVERY", "1")))

    args = ap.parse_args()

    # Management mode: synchronous, then exit
    if args.manage:
        raise SystemExit(run_manage(args))

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    # CSV logger
    csv_logger = None
    if args.csv_log:
        csv_logger = CsvAsyncLogger(args.csv_log, flush_every=args.csv_flush_every)
        await csv_logger.start()
        logging.info("CSV logging enabled: %s", args.csv_log)

    # SQLite billing DB
    db: Optional[DatabaseManager] = None
    if args.db:
        db = DatabaseManager(args.db)
        await db.init_schema()
        logging.info("SQLite billing DB: %s", args.db)

    # IP whitelist
    ipwl = None
    if args.ip_whitelist_file:
        ipwl = IpWhitelist(args.ip_whitelist_file)

    # NextGenSwitch client
    ngs = None
    if args.ngs_base_url and args.ngs_auth_code and args.ngs_auth_secret:
        ngs = NextGenSwitchClient(
            base_url=args.ngs_base_url,
            auth_code=args.ngs_auth_code,
            auth_secret=args.ngs_auth_secret,
            timeout=args.ngs_timeout,
            status_callback=args.ngs_status_callback,
            default_caller=args.ngs_default_from,
        )
        logging.info("NextGenSwitch enabled: %s/api/v1/call", args.ngs_base_url.rstrip("/"))
        if args.ngs_status_callback:
            logging.info("NextGenSwitch statusCallback: %s", args.ngs_status_callback)
        else:
            logging.warning("ngs-status-callback not set; DLR will NOT be triggered.")
    else:
        logging.warning("NextGenSwitch not configured. SUBMIT_SM returns OK but places no calls.")

    server = SmppServer(
        # accept_any_password only when neither --db nor --password is given
        accept_any_password=(args.password is None and db is None),
        fixed_password=args.password,
        ngs=ngs,
        csv_logger=csv_logger,
        ip_whitelist=ipwl,
        dlr_intermediate=args.dlr_intermediate,
        db=db,
    )

    http_host, http_port_s = args.http_listen.rsplit(":", 1)
    http_port = int(http_port_s)
    loop = asyncio.get_running_loop()
    start_callback_http_server(loop, server, http_host, http_port, args.http_path)

    host, port_s = args.listen.rsplit(":", 1)
    port = int(port_s)

    srv = await asyncio.start_server(server.handle_client, host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in srv.sockets or [])
    logging.info("SMPP server listening on %s", addrs)

    try:
        async with srv:
            await srv.serve_forever()
    finally:
        if getattr(server, "_httpd", None):
            try:
                server._httpd.shutdown()  # type: ignore
            except Exception:
                pass
        if csv_logger:
            await csv_logger.stop()
        if db:
            db.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
