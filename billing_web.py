#!/usr/bin/env python3
"""
billing_web.py — Web admin for smpp_server SQLite billing DB.
Reads DB_PATH, WEB_PASSWORD, WEB_SECRET_KEY, WEB_HOST, WEB_PORT from .env.

Run:  python3.11 billing_web.py
"""

import argparse
import hashlib
import json
import os
import queue
import secrets
import socket as _socket
import sqlite3
import signal
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, Response, flash, g, redirect, render_template_string,
                   request, session, stream_with_context, url_for)
from jinja2 import ChoiceLoader, DictLoader

# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------
def _load_dotenv(path=None):
    p = Path(path) if path else Path(__file__).with_name(".env")
    if not p.exists():
        return
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if len(v) >= 2 and v[0] in ('"', "'") and v[-1] == v[0]:
                v = v[1:-1]
            if k and k not in os.environ:
                os.environ[k] = v

_load_dotenv()

DB_PATH      = os.environ.get("DB_PATH",         "./smpp.db")
WEB_HOST     = os.environ.get("WEB_HOST",        "0.0.0.0")
WEB_PORT     = int(os.environ.get("WEB_PORT",    "8888"))
WEB_PASSWORD = os.environ.get("WEB_PASSWORD",    "changeme")
SECRET_KEY   = os.environ.get("WEB_SECRET_KEY",  secrets.token_hex(16))

# Parse SMPP_LISTEN → default host/port for the test form
_smpp_listen  = os.environ.get("SMPP_LISTEN", "127.0.0.1:2775")
_smpp_parts   = _smpp_listen.rsplit(":", 1)
SMPP_DEF_HOST = _smpp_parts[0] if len(_smpp_parts) == 2 else "127.0.0.1"
SMPP_DEF_PORT = int(_smpp_parts[1]) if len(_smpp_parts) == 2 else 2775

# Parse HTTP_LISTEN → local URL to POST fake callbacks in Simulate DLR
_http_listen      = os.environ.get("HTTP_LISTEN", "0.0.0.0:8080")
_http_path        = os.environ.get("HTTP_PATH",   "/ngs/status")
_http_port        = int(_http_listen.rsplit(":", 1)[-1])
HTTP_CALLBACK_LOCAL_URL   = f"http://127.0.0.1:{_http_port}{_http_path}"
NGS_STATUS_CALLBACK_URL   = os.environ.get("NGS_STATUS_CALLBACK", "")

PJSIP_CONF         = os.environ.get("PJSIP_CONF",
                         str(Path(__file__).parent / "transcoder" / "config" / "pjsip.conf"))
ASTERISK_CONTAINER = os.environ.get("ASTERISK_CONTAINER", "asterisk15-g729")

SMPP_PID_FILE = Path(__file__).parent / "smpp_server.pid"
SMPP_LOG_FILE = Path(__file__).parent / "smpp_server.log"
SMPP_SERVER   = Path(__file__).parent / "smpp_server.py"
SMPP_PYTHON   = os.environ.get("SMPP_PYTHON", sys.executable)

_SMPP_CONFIG_GROUPS = [
    ("Listen", [
        ("SMPP_LISTEN",  "SMPP Listen (host:port)",          "text"),
        ("HTTP_LISTEN",  "HTTP Callback Listen (host:port)", "text"),
        ("HTTP_PATH",    "HTTP Callback Path",               "text"),
    ]),
    ("NextGenSwitch", [
        ("NGS_BASE_URL",        "Base URL",              "text"),
        ("NGS_AUTH_CODE",       "Auth Code",             "text"),
        ("NGS_AUTH_SECRET",     "Auth Secret",           "text"),
        ("NGS_STATUS_CALLBACK", "Status Callback URL",   "text"),
        ("NGS_TIMEOUT",         "Timeout (s)",           "number"),
    ]),
    ("Files & Options", [
        ("DB_PATH",           "Database Path",       "text"),
        ("CSV_LOG",           "CSV Log Path",        "text"),
        ("IP_WHITELIST_FILE", "IP Whitelist File",   "text"),
        ("LOG_LEVEL",         "Log Level",           "select:DEBUG,INFO,WARNING,ERROR"),
        ("DLR_INTERMEDIATE",  "DLR Intermediate",    "select:true,false"),
    ]),
]

DOCKER_CONFIG_PATH = Path(__file__).parent / "docker_run.json"
_DOCKER_DEFAULTS   = {
    "image":     "asterisk15-g729",
    "container": "asterisk15-g729",
    "bind_ip":   "57.128.20.2",
    "sip_port":  "5060",
    "rtp_start": "10000",
    "rtp_end":   "10100",
}

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()


def query(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def query_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def execute(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


# ---------------------------------------------------------------------------
# PJSIP config helpers
# ---------------------------------------------------------------------------
def _pjsip_parse():
    stanzas = []
    current_name = None
    current_opts = {}
    try:
        with open(PJSIP_CONF, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("[") and "]" in line:
                    if current_name is not None:
                        stanzas.append((current_name, current_opts))
                    current_name = line[1:line.index("]")]
                    current_opts = {}
                elif "=" in line and not line.startswith(";"):
                    k, _, v = line.partition("=")
                    current_opts[k.strip()] = v.split(";")[0].strip()
    except FileNotFoundError:
        pass
    if current_name is not None:
        stanzas.append((current_name, current_opts))
    return stanzas


def _pjsip_data():
    by_name = {}
    for name, opts in _pjsip_parse():
        by_name.setdefault(name, []).append(opts)

    transport = {}
    for stanza in by_name.get("transport-udp", []):
        transport.update(stanza)

    endpoints, trunks = [], []
    for name, stanza_list in by_name.items():
        if name == "transport-udp":
            continue
        type_map = {s.get("type", ""): s for s in stanza_list}
        if "auth" in type_map:
            auth = type_map["auth"]
            ep   = type_map.get("endpoint", {})
            endpoints.append({
                "name":         name,
                "username":     auth.get("username", name),
                "password":     auth.get("password", ""),
                "codecs":       ep.get("allow", "ulaw,alaw"),
                "context":      ep.get("context", "from-users"),
                "direct_media": ep.get("direct_media", "no"),
                "permit_ip":    ep.get("contact_permit", ""),
            })
        elif "aor" in type_map:
            aor = type_map["aor"]
            ep  = type_map.get("endpoint", {})
            trunks.append({
                "name":              name,
                "contact":           aor.get("contact", ""),
                "qualify_frequency": aor.get("qualify_frequency", "60"),
                "codecs":            ep.get("allow", "g729"),
                "context":           ep.get("context", "from-trunk"),
            })

    return {"transport": transport, "endpoints": endpoints, "trunks": trunks}


def _pjsip_write(data):
    t = data.get("transport", {})
    lines = [
        "[transport-udp]",
        "type=transport",
        "protocol=udp",
        f"bind={t.get('bind', '0.0.0.0:5060')}",
    ]
    if t.get("external_signaling_address"):
        lines.append(f"external_signaling_address={t['external_signaling_address']}")
    if t.get("external_media_address"):
        lines.append(f"external_media_address={t['external_media_address']}")
    lines.append("")

    for ep in data.get("endpoints", []):
        n = ep["name"]
        lines += [
            f"[{n}]", "type=auth", "auth_type=userpass",
            f"username={ep.get('username', n)}", f"password={ep['password']}", "",
            f"[{n}]", "type=aor", "max_contacts=1", "remove_existing=yes", "",
            f"[{n}]", "type=endpoint", "transport=transport-udp",
            f"context={ep.get('context', 'from-users')}",
            "disallow=all", f"allow={ep.get('codecs', 'ulaw,alaw')}",
            f"auth={n}", f"aors={n}",
            f"direct_media={ep.get('direct_media', 'no')}",
            "rtp_symmetric=yes", "force_rport=yes", "rewrite_contact=yes",
        ]
        if ep.get("permit_ip"):
            lines.append(f"contact_permit={ep['permit_ip']}")
        lines.append("")

    for trunk in data.get("trunks", []):
        n = trunk["name"]
        lines += [
            f"[{n}]", "type=aor",
            f"contact={trunk.get('contact', '')}",
            f"qualify_frequency={trunk.get('qualify_frequency', '60')}", "",
            f"[{n}]", "type=endpoint", "transport=transport-udp",
            f"context={trunk.get('context', 'from-trunk')}",
            "disallow=all", f"allow={trunk.get('codecs', 'g729')}",
            f"aors={n}", "direct_media=no", "",
        ]

    with open(PJSIP_CONF, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Docker config helpers
# ---------------------------------------------------------------------------
def _docker_cfg_read():
    try:
        with open(DOCKER_CONFIG_PATH, encoding="utf-8") as f:
            return {**_DOCKER_DEFAULTS, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_DOCKER_DEFAULTS)


def _docker_cfg_write(cfg):
    with open(DOCKER_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def _docker_transcoder_dir():
    return str(Path(PJSIP_CONF).parent.parent)


def _docker_run_args(cfg):
    td = _docker_transcoder_dir()
    return [
        "docker", "run", "-d",
        "--name", cfg["container"],
        "--restart", "unless-stopped",
        "-p", f"{cfg['bind_ip']}:{cfg['sip_port']}:{cfg['sip_port']}/udp",
        "-p", f"{cfg['bind_ip']}:{cfg['rtp_start']}-{cfg['rtp_end']}:{cfg['rtp_start']}-{cfg['rtp_end']}/udp",
        "-v", f"{td}/config:/etc/asterisk",
        "-v", f"{td}/logs:/var/log/asterisk",
        "-v", f"{td}/spool:/var/spool/asterisk",
        cfg["image"],
    ]


def _docker_run_cmd_str(cfg):
    td = _docker_transcoder_dir()
    return (
        f"docker run -d \\\n"
        f"  --name {cfg['container']} \\\n"
        f"  --restart unless-stopped \\\n"
        f"  -p {cfg['bind_ip']}:{cfg['sip_port']}:{cfg['sip_port']}/udp \\\n"
        f"  -p {cfg['bind_ip']}:{cfg['rtp_start']}-{cfg['rtp_end']}:{cfg['rtp_start']}-{cfg['rtp_end']}/udp \\\n"
        f"  -v {td}/config:/etc/asterisk \\\n"
        f"  -v {td}/logs:/var/log/asterisk \\\n"
        f"  -v {td}/spool:/var/spool/asterisk \\\n"
        f"  {cfg['image']}"
    )


def _docker_status(container):
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else "not found"
    except Exception:
        return "error"


# ---------------------------------------------------------------------------
# SMPP service helpers
# ---------------------------------------------------------------------------
def _smpp_status():
    try:
        pid = int(SMPP_PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return "stopped", None
    try:
        os.kill(pid, 0)
        return "running", pid
    except ProcessLookupError:
        SMPP_PID_FILE.unlink(missing_ok=True)
        return "stopped", None
    except PermissionError:
        return "running", pid


def _smpp_start():
    status, _ = _smpp_status()
    if status == "running":
        return False, "Already running"
    try:
        log_f = open(SMPP_LOG_FILE, "a")
        proc  = subprocess.Popen(
            [SMPP_PYTHON, str(SMPP_SERVER)],
            stdout=log_f, stderr=log_f,
            cwd=str(SMPP_SERVER.parent),
            start_new_session=True,
        )
        log_f.close()
        SMPP_PID_FILE.write_text(str(proc.pid))
        return True, f"Started (pid={proc.pid})"
    except Exception as exc:
        return False, str(exc)


def _smpp_stop():
    status, pid = _smpp_status()
    if status != "running" or pid is None:
        return False, "Not running"
    try:
        os.kill(pid, signal.SIGTERM)
        SMPP_PID_FILE.unlink(missing_ok=True)
        return True, f"Stopped (pid={pid})"
    except ProcessLookupError:
        SMPP_PID_FILE.unlink(missing_ok=True)
        return True, "Process already gone"
    except Exception as exc:
        return False, str(exc)


def _env_read():
    path = Path(__file__).parent / ".env"
    result = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip()
                if len(v) >= 2 and v[0] in ('"', "'") and v[-1] == v[0]:
                    v = v[1:-1]
                result[k] = v
    except FileNotFoundError:
        pass
    return result


def _env_write(updates: dict):
    path = Path(__file__).parent / ".env"
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    written = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        k = stripped.partition("=")[0].strip()
        if k in updates:
            new_lines.append(f"{k}={updates[k]}\n")
            written.add(k)
        else:
            new_lines.append(line)

    for k, v in updates.items():
        if k not in written:
            new_lines.append(f"{k}={v}\n")

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# SMPP test runner (background thread + SSE)
# ---------------------------------------------------------------------------
_test_jobs: dict = {}          # job_id → {q, done, success}
_test_jobs_lock = threading.Lock()

# SMPP constants (local to avoid import dependency)
_B_TRX      = 0x00000009
_B_TRX_RESP = 0x80000009
_SUB_SM     = 0x00000004
_SUB_RESP   = 0x80000004
_DEL_SM     = 0x00000005
_DEL_RESP   = 0x80000005
_ENQ        = 0x00000015
_ENQ_RESP   = 0x80000015
_UNBIND     = 0x00000006
_UNBIND_RESP= 0x80000006
_ESME_ROK   = 0x00000000
_HDR        = ">IIII"
_HDR_LEN    = 16


def _cstr(s: str) -> bytes:
    return s.encode("utf-8", errors="replace") + b"\x00"


def _build_pdu(cmd: int, status: int, seq: int, body: bytes = b"") -> bytes:
    ln = _HDR_LEN + len(body)
    return struct.pack(_HDR, ln, cmd, status, seq) + body


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def _recv_pdu(sock):
    hdr = _recv_exact(sock, 4)
    (pdu_len,) = struct.unpack(">I", hdr)
    rest = _recv_exact(sock, pdu_len - 4)
    pdu = hdr + rest
    _, cmd_id, status, seq = struct.unpack(_HDR, pdu[:_HDR_LEN])
    return cmd_id, status, seq, pdu[_HDR_LEN:]


def _read_cstr(buf: bytes, off: int):
    end = buf.find(b"\x00", off)
    if end == -1:
        return "", len(buf)
    return buf[off:end].decode("utf-8", errors="replace"), end + 1


def _smpp_test_runner(job_id: str, host: str, port: int, system_id: str,
                      password: str, src: str, dst: str, text: str,
                      dlr_timeout: float, enquire_interval: float,
                      request_dlr: bool):
    job = _test_jobs[job_id]
    q   = job["q"]

    def emit(msg, level="info"):
        q.put({"level": level, "text": msg})

    def finish(success: bool):
        job["done"]    = True
        job["success"] = success
        q.put({"level": "done", "success": success})

    try:
        emit(f"Connecting to {host}:{port} …")
        with _socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(5)
            seq = 1

            # ── BIND ─────────────────────────────────────────────────────
            bind_body = (
                _cstr(system_id) + _cstr(password) + _cstr("") +
                bytes([0x34, 0x00, 0x00]) + _cstr("")
            )
            sock.sendall(_build_pdu(_B_TRX, 0, seq, bind_body))
            cmd_id, status, _, _ = _recv_pdu(sock)

            if cmd_id != _B_TRX_RESP:
                raise RuntimeError(f"Expected BIND_TRANSCEIVER_RESP, got 0x{cmd_id:08x}")
            if status != _ESME_ROK:
                emit(f"BIND FAILED  status=0x{status:08x}", "error")
                return finish(False)

            emit(f"✓  Bound as '{system_id}'", "success")
            seq += 1

            # ── SUBMIT_SM ─────────────────────────────────────────────────
            msg_bytes = text.encode("utf-8", errors="replace")
            if len(msg_bytes) > 254:
                emit("Message truncated to 254 bytes", "warning")
                msg_bytes = msg_bytes[:254]

            reg_del = 0x01 if request_dlr else 0x00
            sub_body = (
                _cstr("") +
                bytes([0x00, 0x00]) + _cstr(src) +
                bytes([0x00, 0x00]) + _cstr(dst) +
                bytes([0x00, 0x00, 0x00]) +     # esm_class, protocol_id, priority_flag
                _cstr("") + _cstr("") +          # schedule_delivery_time, validity_period
                bytes([reg_del, 0x00, 0x00, 0x00]) +
                bytes([len(msg_bytes)]) + msg_bytes
            )
            emit(f"Sending SUBMIT_SM  from={src}  to={dst}")
            emit(f'  text: "{text}"')
            sock.sendall(_build_pdu(_SUB_SM, 0, seq, sub_body))
            cmd_id, status, _, rbody = _recv_pdu(sock)

            if cmd_id != _SUB_RESP:
                raise RuntimeError(f"Expected SUBMIT_SM_RESP, got 0x{cmd_id:08x}")

            msg_id = rbody.split(b"\x00", 1)[0].decode("utf-8", errors="replace") if rbody else ""

            if status != _ESME_ROK:
                emit(f"SUBMIT FAILED  status=0x{status:08x}", "error")
                return finish(False)

            emit(f"✓  SUBMIT_SM_RESP OK  message_id={msg_id!r}", "success")
            job["message_id"] = msg_id
            # special event so the UI can show Simulate DLR controls
            q.put({"level": "msgid", "message_id": msg_id,
                   "text": f"message_id={msg_id!r}"})
            seq += 1

            if not request_dlr:
                sock.sendall(_build_pdu(_UNBIND, 0, seq))
                try:
                    _recv_pdu(sock)
                except Exception:
                    pass
                emit("✓  Unbound. Done (DLR not requested).", "success")
                return finish(True)

            # ── Wait for DLR ──────────────────────────────────────────────
            emit(f"Waiting for DLR  (timeout={int(dlr_timeout)}s) …")
            deadline     = time.time() + dlr_timeout
            next_enquire = time.time() + enquire_interval
            got_final    = False

            while time.time() < deadline:
                # keepalive
                if enquire_interval > 0 and time.time() >= next_enquire:
                    try:
                        sock.sendall(_build_pdu(_ENQ, 0, seq))
                        ecmd, est, _, _ = _recv_pdu(sock)
                        emit(f"ENQUIRE_LINK_RESP  status=0x{est:08x}")
                        seq += 1
                    except _socket.timeout:
                        emit("ENQUIRE_LINK timeout (continuing)", "warning")
                    next_enquire = time.time() + enquire_interval

                try:
                    cmd_id, status, rseq, body = _recv_pdu(sock)
                except _socket.timeout:
                    secs_left = int(deadline - time.time())
                    emit(f"  … waiting ({secs_left}s left)")
                    continue

                if cmd_id == _DEL_SM:
                    # Parse deliver_sm
                    off = 0
                    _, off = _read_cstr(body, off)
                    off += 2
                    dlr_src, off = _read_cstr(body, off)
                    off += 2
                    dlr_dst, off = _read_cstr(body, off)
                    esm = body[off] if off < len(body) else 0
                    off += 3
                    _, off = _read_cstr(body, off)
                    _, off = _read_cstr(body, off)
                    off += 4
                    sm_len = body[off] if off < len(body) else 0
                    off += 1
                    sm = body[off:off + sm_len].decode("utf-8", errors="replace")

                    emit(f"DELIVER_SM  src={dlr_src!r}  dst={dlr_dst!r}  esm=0x{esm:02x}")
                    emit(f'  receipt: "{sm}"')

                    # ACK
                    sock.sendall(_build_pdu(_DEL_RESP, _ESME_ROK, rseq))

                    parts = sm.split()
                    tid  = next((p[3:]  for p in parts if p.startswith("id:")),   None)
                    stat = next((p[5:].upper() for p in parts if p.startswith("stat:")), None)

                    if tid == msg_id and stat in {"DELIVRD", "UNDELIV", "REJECTD", "EXPIRED"}:
                        lvl = "success" if stat == "DELIVRD" else "warning"
                        emit(f"✓  Final DLR: stat={stat}", lvl)
                        got_final = True
                        break

                elif cmd_id == _ENQ:
                    sock.sendall(_build_pdu(_ENQ_RESP, _ESME_ROK, rseq))

                elif cmd_id == _UNBIND:
                    sock.sendall(_build_pdu(_UNBIND_RESP, _ESME_ROK, rseq))
                    emit("Server sent UNBIND.", "warning")
                    break

                else:
                    emit(f"PDU 0x{cmd_id:08x} status=0x{status:08x} seq={rseq} (ignored)")

            if not got_final:
                emit("⚠  DLR timeout — no final receipt received.", "warning")

            # Unbind
            try:
                sock.sendall(_build_pdu(_UNBIND, 0, seq))
                _recv_pdu(sock)
                emit("✓  Unbound cleanly.", "success")
            except Exception:
                pass

            finish(got_final)

    except Exception as exc:
        emit(f"ERROR: {exc}", "error")
        finish(False)


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

BASE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}SMPP Billing{% endblock %}</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <style>
    body { background:#f4f6f9; }
    .navbar { background:#1a1a2e !important; }
    .navbar-brand, .nav-link { color:#eee !important; }
    .nav-link:hover { color:#fff !important; }
    .card { border:none; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.08); }
    .badge-active   { background:#198754; }
    .badge-inactive { background:#dc3545; }
    table { font-size:.9rem; }
    .ledger-charge { color:#dc3545; }
    .ledger-topup  { color:#198754; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg mb-4">
  <div class="container">
    <a class="navbar-brand fw-bold" href="{{ url_for('dashboard') }}">SMPP Billing</a>
    <button class="navbar-toggler" type="button"
            data-bs-toggle="collapse" data-bs-target="#mainNav"
            aria-controls="mainNav" aria-expanded="false" aria-label="Toggle navigation"
            style="border-color:rgba(255,255,255,.3)">
      <span class="navbar-toggler-icon" style="filter:invert(1)"></span>
    </button>
    <div class="collapse navbar-collapse" id="mainNav">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('add_user') }}">Add User</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('sessions_view') }}">Sessions</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('test_page') }}">Test SMS</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('smpp_page') }}">SMPP Service</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('sip_accounts') }}">SIP Accounts</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('docker_page') }}">Docker</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
      </ul>
    </div>
  </div>
</nav>
<div class="container pb-5">
  {% with msgs = get_flashed_messages(with_categories=true) %}
    {% for cat, msg in msgs %}
      <div class="alert alert-{{ 'success' if cat == 'success' else 'danger' }} alert-dismissible fade show">
        {{ msg }}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    {% endfor %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
LOGIN_TMPL = """\
{% extends 'base.html' %}
{% block title %}Login — SMPP Billing{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-4">
    <div class="card p-4 mt-5">
      <h4 class="mb-3 text-center">SMPP Billing Login</h4>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input type="password" name="password" class="form-control" autofocus required>
        </div>
        <button class="btn btn-primary w-100">Login</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == WEB_PASSWORD:
            session["logged_in"] = True
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Wrong password.", "error")
    return render_template_string(LOGIN_TMPL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
DASHBOARD_TMPL = """\
{% extends 'base.html' %}
{% block title %}Dashboard — SMPP Billing{% endblock %}
{% block content %}
<div class="row mb-3">
  <div class="col"><h4 class="fw-bold">Users</h4></div>
  <div class="col text-end">
    <a href="{{ url_for('add_user') }}" class="btn btn-sm btn-primary">+ Add User</a>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-2 fw-bold text-primary">{{ stats.total_users }}</div>
      <div class="text-muted">Total Users</div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-2 fw-bold text-success">{{ stats.active_users }}</div>
      <div class="text-muted">Active Users</div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-2 fw-bold text-info">{{ stats.total_messages }}</div>
      <div class="text-muted">Total Messages</div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-2 fw-bold text-warning">{{ "%.4f"|format(stats.total_revenue) }}</div>
      <div class="text-muted">Total Revenue</div>
    </div>
  </div>
</div>

<div class="card">
  <div class="table-responsive">
    <table class="table table-hover align-middle mb-0">
      <thead class="table-dark">
        <tr>
          <th>system_id</th><th>Status</th>
          <th class="text-end">Balance</th><th class="text-end">Rate/SMS</th>
          <th class="text-end">Messages</th><th class="text-end">Spent</th>
          <th>Created</th><th></th>
        </tr>
      </thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>
            <a href="{{ url_for('user_detail', system_id=u.system_id) }}"
               class="fw-semibold text-decoration-none">{{ u.system_id }}</a>
          </td>
          <td>
            <span class="badge {{ 'badge-active' if u.is_active else 'badge-inactive' }}">
              {{ 'Active' if u.is_active else 'Disabled' }}
            </span>
          </td>
          <td class="text-end fw-semibold
              {{ 'text-danger' if u.credit_balance < u.rate_per_sms else '' }}">
            {{ "%.4f"|format(u.credit_balance) }}
          </td>
          <td class="text-end">{{ "%.4f"|format(u.rate_per_sms) }}</td>
          <td class="text-end">{{ u.total_msgs }}</td>
          <td class="text-end">{{ "%.4f"|format(u.total_spent) }}</td>
          <td class="text-muted small">{{ u.created_at[:10] }}</td>
          <td class="text-end">
            <a href="{{ url_for('topup', system_id=u.system_id) }}"
               class="btn btn-sm btn-outline-success me-1">Topup</a>
            <a href="{{ url_for('edit_user', system_id=u.system_id) }}"
               class="btn btn-sm btn-outline-secondary">Edit</a>
          </td>
        </tr>
        {% else %}
        <tr>
          <td colspan="8" class="text-center text-muted py-4">
            No users yet. <a href="{{ url_for('add_user') }}">Add one.</a>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""


@app.route("/")
@login_required
def dashboard():
    users = query("""
        SELECT u.*, COUNT(m.id) as total_msgs, COALESCE(SUM(m.charge),0) as total_spent
        FROM users u LEFT JOIN messages m ON m.user_id = u.id
        GROUP BY u.id ORDER BY u.id
    """)
    stats_row = query_one("""
        SELECT
          (SELECT COUNT(*)        FROM users)              as total_users,
          (SELECT SUM(is_active)  FROM users)              as active_users,
          (SELECT COUNT(*)        FROM messages)           as total_messages,
          (SELECT COALESCE(SUM(charge), 0) FROM messages) as total_revenue
    """)
    return render_template_string(DASHBOARD_TMPL, users=users, stats=stats_row)


# ---------------------------------------------------------------------------
# User detail
# ---------------------------------------------------------------------------
USER_TMPL = """\
{% extends 'base.html' %}
{% block title %}{{ user.system_id }} — SMPP Billing{% endblock %}
{% block content %}
<div class="d-flex align-items-center mb-3 gap-2">
  <a href="{{ url_for('dashboard') }}" class="btn btn-sm btn-outline-secondary">&larr; Back</a>
  <h4 class="fw-bold mb-0">{{ user.system_id }}</h4>
  <span class="badge {{ 'badge-active' if user.is_active else 'badge-inactive' }}">
    {{ 'Active' if user.is_active else 'Disabled' }}
  </span>
</div>

<div class="row g-3 mb-4">
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-3 fw-bold
          {{ 'text-danger' if user.credit_balance < user.rate_per_sms else 'text-success' }}">
        {{ "%.4f"|format(user.credit_balance) }}
      </div>
      <div class="text-muted">Credit Balance</div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-3 fw-bold text-secondary">{{ "%.4f"|format(user.rate_per_sms) }}</div>
      <div class="text-muted">Rate / SMS</div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-3 fw-bold text-info">{{ msg_stats.total or 0 }}</div>
      <div class="text-muted">Total Messages</div>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card p-3 text-center">
      <div class="fs-3 fw-bold text-warning">{{ "%.4f"|format(msg_stats.spent or 0) }}</div>
      <div class="text-muted">Total Spent</div>
    </div>
  </div>
</div>

<div class="d-flex gap-2 mb-4">
  <a href="{{ url_for('topup', system_id=user.system_id) }}" class="btn btn-success btn-sm">Topup Credit</a>
  <a href="{{ url_for('edit_user', system_id=user.system_id) }}" class="btn btn-secondary btn-sm">Edit User</a>
</div>

<div class="row g-4">
  <div class="col-lg-6">
    <h6 class="fw-bold">Recent Ledger <span class="text-muted fw-normal">(last 20)</span></h6>
    <div class="card">
      <div class="table-responsive">
        <table class="table table-sm mb-0">
          <thead class="table-light">
            <tr><th>Time</th><th>Type</th><th class="text-end">Amount</th>
                <th class="text-end">Balance after</th><th>Note</th></tr>
          </thead>
          <tbody>
            {% for r in ledger %}
            <tr>
              <td class="text-muted small">{{ r.ts[:19] }}</td>
              <td><span class="fw-semibold
                  {{ 'ledger-topup' if r.type == 'topup' else 'ledger-charge' }}">
                {{ r.type }}</span></td>
              <td class="text-end">{{ "%.4f"|format(r.amount) }}</td>
              <td class="text-end">{{ "%.4f"|format(r.balance_after) }}</td>
              <td class="small text-muted">{{ r.note }}</td>
            </tr>
            {% else %}
            <tr><td colspan="5" class="text-center text-muted">No ledger entries.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="col-lg-6">
    <h6 class="fw-bold">Recent Messages <span class="text-muted fw-normal">(last 20)</span></h6>
    <div class="card">
      <div class="table-responsive">
        <table class="table table-sm mb-0">
          <thead class="table-light">
            <tr><th>Time</th><th>From</th><th>To</th>
                <th>OK</th><th>DLR</th><th class="text-end">Charge</th></tr>
          </thead>
          <tbody>
            {% for m in messages %}
            <tr>
              <td class="text-muted small">{{ m.submit_ts[:19] }}</td>
              <td class="small">{{ m.src }}</td>
              <td class="small">{{ m.dst }}</td>
              <td>{{ '✓' if m.ngs_ok else '✗' }}</td>
              <td class="small">{{ m.dlr_stat or '—' }}</td>
              <td class="text-end">{{ "%.4f"|format(m.charge) }}</td>
            </tr>
            {% else %}
            <tr><td colspan="6" class="text-center text-muted">No messages.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/user/<system_id>")
@login_required
def user_detail(system_id):
    user = query_one("SELECT * FROM users WHERE system_id = ?", (system_id,))
    if not user:
        flash(f"User '{system_id}' not found.", "error")
        return redirect(url_for("dashboard"))
    msg_stats = query_one(
        "SELECT COUNT(*) as total, COALESCE(SUM(charge),0) as spent "
        "FROM messages WHERE user_id = ?", (user["id"],)
    )
    ledger   = query("SELECT * FROM billing_ledger WHERE user_id = ? ORDER BY id DESC LIMIT 20", (user["id"],))
    messages = query("SELECT * FROM messages WHERE user_id = ? ORDER BY id DESC LIMIT 20", (user["id"],))
    return render_template_string(USER_TMPL, user=user, msg_stats=msg_stats,
                                  ledger=ledger, messages=messages)


# ---------------------------------------------------------------------------
# Add user
# ---------------------------------------------------------------------------
ADD_USER_TMPL = """\
{% extends 'base.html' %}
{% block title %}Add User — SMPP Billing{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <a href="{{ url_for('dashboard') }}" class="btn btn-sm btn-outline-secondary mb-3">&larr; Back</a>
    <div class="card p-4">
      <h5 class="mb-3 fw-bold">Add New User</h5>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">system_id <span class="text-danger">*</span></label>
          <input name="system_id" class="form-control" required autofocus>
        </div>
        <div class="mb-3">
          <label class="form-label">Password <span class="text-danger">*</span></label>
          <input type="password" name="password" class="form-control" required>
        </div>
        <div class="row">
          <div class="col mb-3">
            <label class="form-label">Initial Credit</label>
            <input type="number" step="0.0001" name="credit" value="0" class="form-control">
          </div>
          <div class="col mb-3">
            <label class="form-label">Rate / SMS</label>
            <input type="number" step="0.0001" name="rate" value="0" class="form-control">
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">Notes</label>
          <input name="notes" class="form-control">
        </div>
        <button class="btn btn-primary w-100">Create User</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/add-user", methods=["GET", "POST"])
@login_required
def add_user():
    if request.method == "POST":
        system_id = request.form.get("system_id", "").strip()
        password  = request.form.get("password", "")
        credit    = float(request.form.get("credit") or 0)
        rate      = float(request.form.get("rate")   or 0)
        notes     = request.form.get("notes", "").strip()

        if not system_id or not password:
            flash("system_id and password are required.", "error")
            return render_template_string(ADD_USER_TMPL)

        try:
            db  = get_db()
            now = _utc_now()
            db.execute(
                "INSERT INTO users (system_id, password_hash, is_active, credit_balance, "
                "rate_per_sms, created_at, notes) VALUES (?, ?, 1, ?, ?, ?, ?)",
                (system_id, _hash_password(password), credit, rate, now, notes)
            )
            if credit > 0:
                uid = db.execute("SELECT id FROM users WHERE system_id = ?",
                                 (system_id,)).fetchone()["id"]
                db.execute(
                    "INSERT INTO billing_ledger (user_id, ts, type, amount, balance_after, note) "
                    "VALUES (?, ?, 'topup', ?, ?, 'initial credit')",
                    (uid, now, credit, credit)
                )
            db.commit()
            flash(f"User '{system_id}' created.", "success")
            return redirect(url_for("user_detail", system_id=system_id))
        except sqlite3.IntegrityError:
            flash(f"system_id '{system_id}' already exists.", "error")

    return render_template_string(ADD_USER_TMPL)


# ---------------------------------------------------------------------------
# Topup
# ---------------------------------------------------------------------------
TOPUP_TMPL = """\
{% extends 'base.html' %}
{% block title %}Topup — {{ system_id }}{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-4">
    <a href="{{ url_for('user_detail', system_id=system_id) }}"
       class="btn btn-sm btn-outline-secondary mb-3">&larr; Back</a>
    <div class="card p-4">
      <h5 class="mb-1 fw-bold">Topup Credit</h5>
      <p class="text-muted mb-3">
        {{ system_id }} — current balance: <strong>{{ "%.4f"|format(balance) }}</strong>
      </p>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Amount <span class="text-danger">*</span></label>
          <input type="number" step="0.0001" min="0.0001" name="amount"
                 class="form-control" required autofocus>
        </div>
        <div class="mb-3">
          <label class="form-label">Note</label>
          <input name="note" class="form-control" placeholder="optional">
        </div>
        <button class="btn btn-success w-100">Add Credit</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/topup", methods=["GET", "POST"])
@app.route("/topup/<system_id>", methods=["GET", "POST"])
@login_required
def topup(system_id=None):
    if not system_id:
        system_id = request.args.get("system_id", "")

    user = query_one("SELECT * FROM users WHERE system_id = ?", (system_id,))
    if not user:
        flash(f"User '{system_id}' not found.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        amount = float(request.form.get("amount") or 0)
        note   = request.form.get("note", "").strip() or "manual topup"
        if amount <= 0:
            flash("Amount must be positive.", "error")
        else:
            db = get_db()
            db.execute("UPDATE users SET credit_balance = credit_balance + ? WHERE id = ?",
                       (amount, user["id"]))
            new_bal = db.execute("SELECT credit_balance FROM users WHERE id = ?",
                                 (user["id"],)).fetchone()["credit_balance"]
            db.execute(
                "INSERT INTO billing_ledger (user_id, ts, type, amount, balance_after, note) "
                "VALUES (?, ?, 'topup', ?, ?, ?)",
                (user["id"], _utc_now(), amount, new_bal, note)
            )
            db.commit()
            flash(f"Added {amount:.4f}. New balance: {new_bal:.4f}", "success")
            return redirect(url_for("user_detail", system_id=system_id))

    return render_template_string(TOPUP_TMPL, system_id=system_id, balance=user["credit_balance"])


# ---------------------------------------------------------------------------
# Edit user
# ---------------------------------------------------------------------------
EDIT_TMPL = """\
{% extends 'base.html' %}
{% block title %}Edit — {{ user.system_id }}{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <a href="{{ url_for('user_detail', system_id=user.system_id) }}"
       class="btn btn-sm btn-outline-secondary mb-3">&larr; Back</a>

    <div class="card p-4 mb-3">
      <h5 class="fw-bold mb-3">Edit — {{ user.system_id }}</h5>
      <form method="post" action="{{ url_for('edit_user', system_id=user.system_id) }}">
        <input type="hidden" name="action" value="settings">
        <div class="mb-3">
          <label class="form-label">Rate / SMS</label>
          <input type="number" step="0.0001" name="rate"
                 value="{{ user.rate_per_sms }}" class="form-control">
        </div>
        <div class="mb-3">
          <label class="form-label">Notes</label>
          <input name="notes" value="{{ user.notes }}" class="form-control">
        </div>
        <div class="mb-3">
          <label class="form-label">Status</label>
          <select name="is_active" class="form-select">
            <option value="1" {{ 'selected' if user.is_active }}>Active</option>
            <option value="0" {{ 'selected' if not user.is_active }}>Disabled</option>
          </select>
        </div>
        <button class="btn btn-primary">Save Settings</button>
      </form>
    </div>

    <div class="card p-4">
      <h6 class="fw-bold mb-3">Change Password</h6>
      <form method="post" action="{{ url_for('edit_user', system_id=user.system_id) }}">
        <input type="hidden" name="action" value="passwd">
        <div class="mb-3">
          <label class="form-label">New Password <span class="text-danger">*</span></label>
          <input type="password" name="password" class="form-control" required>
        </div>
        <button class="btn btn-warning">Update Password</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/edit/<system_id>", methods=["GET", "POST"])
@login_required
def edit_user(system_id):
    user = query_one("SELECT * FROM users WHERE system_id = ?", (system_id,))
    if not user:
        flash(f"User '{system_id}' not found.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "settings":
            rate      = float(request.form.get("rate") or 0)
            is_active = int(request.form.get("is_active", 1))
            notes     = request.form.get("notes", "").strip()
            execute("UPDATE users SET rate_per_sms=?, is_active=?, notes=? WHERE system_id=?",
                    (rate, is_active, notes, system_id))
            flash("Settings saved.", "success")

        elif action == "passwd":
            password = request.form.get("password", "")
            if not password:
                flash("Password cannot be empty.", "error")
            else:
                execute("UPDATE users SET password_hash=? WHERE system_id=?",
                        (_hash_password(password), system_id))
                flash("Password updated.", "success")

        return redirect(url_for("edit_user", system_id=system_id))

    user = query_one("SELECT * FROM users WHERE system_id = ?", (system_id,))
    return render_template_string(EDIT_TMPL, user=user)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
SESSIONS_TMPL = """\
{% extends 'base.html' %}
{% block title %}Sessions — SMPP Billing{% endblock %}
{% block content %}
<h5 class="fw-bold mb-3">Recent Sessions <small class="text-muted fs-6">(last 100)</small></h5>
<div class="card">
  <div class="table-responsive">
    <table class="table table-sm align-middle mb-0">
      <thead class="table-dark">
        <tr><th>User</th><th>Peer</th><th>Mode</th>
            <th>Start</th><th>End</th><th>Duration</th></tr>
      </thead>
      <tbody>
        {% for s in sessions %}
        <tr>
          <td>
            <a href="{{ url_for('user_detail', system_id=s.system_id) }}">{{ s.system_id }}</a>
          </td>
          <td class="small text-muted">{{ s.peer }}</td>
          <td>{{ s.bind_mode }}</td>
          <td class="small">{{ s.session_start[:19] }}</td>
          <td class="small">
            {% if s.session_end %}{{ s.session_end[:19] }}
            {% else %}<span class="badge bg-success">live</span>{% endif %}
          </td>
          <td class="small text-muted">
            {% if s.session_end %}{{ s.duration }}s{% else %}—{% endif %}
          </td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="text-center text-muted py-4">No sessions.</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""


@app.route("/sessions")
@login_required
def sessions_view():
    rows = query("""
        SELECT s.*, u.system_id,
               CAST((JULIANDAY(COALESCE(s.session_end, DATETIME('now')))
                     - JULIANDAY(s.session_start)) * 86400 AS INTEGER) as duration
        FROM sessions s JOIN users u ON u.id = s.user_id
        ORDER BY s.id DESC LIMIT 100
    """)
    return render_template_string(SESSIONS_TMPL, sessions=rows)


# ---------------------------------------------------------------------------
# Test SMS
# ---------------------------------------------------------------------------
TEST_FORM_TMPL = """\
{% extends 'base.html' %}
{% block title %}Test SMS — SMPP Billing{% endblock %}
{% block content %}
<h4 class="fw-bold mb-4">Test SMS via SMPP</h4>
<div class="row">
  <div class="col-lg-5">
    <div class="card p-4">
      <form method="post" action="{{ url_for('test_run') }}">

        <h6 class="fw-semibold text-muted mb-3">Connection</h6>
        <div class="row mb-3">
          <div class="col-8">
            <label class="form-label">SMPP Host</label>
            <input name="host" value="{{ def_host }}" class="form-control" required>
          </div>
          <div class="col-4">
            <label class="form-label">Port</label>
            <input type="number" name="port" value="{{ def_port }}" class="form-control" required>
          </div>
        </div>

        <h6 class="fw-semibold text-muted mb-3 mt-4">Credentials</h6>
        <div class="mb-3">
          <label class="form-label">system_id</label>
          <select name="system_id" class="form-select" id="sidSelect">
            <option value="">— custom —</option>
            {% for u in users %}
            <option value="{{ u.system_id }}">{{ u.system_id }}
              (bal: {{ "%.2f"|format(u.credit_balance) }})
            </option>
            {% endfor %}
          </select>
        </div>
        <div class="mb-3">
          <label class="form-label">system_id (custom)</label>
          <input name="system_id_custom" id="sidCustom" class="form-control"
                 placeholder="leave blank to use dropdown">
        </div>
        <div class="mb-3">
          <label class="form-label">Password <span class="text-danger">*</span></label>
          <input type="password" name="password" class="form-control" required>
        </div>

        <h6 class="fw-semibold text-muted mb-3 mt-4">Message</h6>
        <div class="row mb-3">
          <div class="col">
            <label class="form-label">Source (from)</label>
            <input name="src" value="1000" class="form-control">
          </div>
          <div class="col">
            <label class="form-label">Destination (to) <span class="text-danger">*</span></label>
            <input name="dst" class="form-control" required placeholder="+1234567890">
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">Message Text <span class="text-danger">*</span></label>
          <textarea name="text" class="form-control" rows="3" required
            >G-241652 is your GOOGLE verification code. Don't share your code with anyone.</textarea>
        </div>

        <h6 class="fw-semibold text-muted mb-3 mt-4">Options</h6>
        <div class="row mb-3">
          <div class="col">
            <label class="form-label">DLR Timeout (s)</label>
            <input type="number" name="dlr_timeout" value="60" class="form-control">
          </div>
          <div class="col">
            <label class="form-label">Enquire Interval (s)</label>
            <input type="number" name="enquire_interval" value="10" class="form-control">
          </div>
        </div>
        <div class="mb-4">
          <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" name="request_dlr"
                   id="dlrCheck" checked>
            <label class="form-check-label" for="dlrCheck">Request Delivery Receipt (DLR)</label>
          </div>
        </div>

        <button class="btn btn-primary w-100 fw-semibold">
          &#9654; Send Test SMS
        </button>
      </form>
    </div>
  </div>

  <div class="col-lg-7 mt-4 mt-lg-0">
    <h6 class="fw-bold mb-2 text-muted">How to use</h6>
    <div class="card p-3 mb-3 small text-muted">
      <ol class="mb-0">
        <li>Select a user from the dropdown (or type a custom system_id).</li>
        <li>Enter the SMPP password for that user.</li>
        <li>Set the destination phone number in E.164 format (+country code).</li>
        <li>Click <strong>Send Test SMS</strong> — a live log will stream below.</li>
        <li>With DLR enabled the test waits for the delivery receipt from NextGenSwitch.</li>
      </ol>
    </div>
    <h6 class="fw-bold mb-2 text-muted">Equivalent CLI command</h6>
    <pre class="card p-3 small" style="background:#1e1e2e;color:#cdd6f4;border-radius:10px"
>python3.11 smpp_test_client_trx.py \\
  --host {{ def_host }} --port {{ def_port }} \\
  --system-id &lt;id&gt; --password &lt;pass&gt; \\
  --src 1000 --dst &lt;phone&gt; \\
  --text "Your OTP is 123456" \\
  --dlr-timeout 60 --enquire-interval 10</pre>
  </div>
</div>
{% endblock %}
"""

TEST_RESULT_TMPL = """\
{% extends 'base.html' %}
{% block title %}Test Result — SMPP Billing{% endblock %}
{% block content %}
<div class="d-flex align-items-center gap-2 mb-3 flex-wrap">
  <a href="{{ url_for('test_page') }}" class="btn btn-sm btn-outline-secondary">&larr; New Test</a>
  <h5 class="fw-bold mb-0">Test Run — Live Log</h5>
  <span id="statusBadge" class="badge bg-secondary">running</span>
</div>

<div class="row g-3">
  <!-- Terminal -->
  <div class="col-lg-8">
    <div id="terminal" style="
      background:#0d1117; color:#c9d1d9; font-family:monospace;
      font-size:.85rem; border-radius:10px; padding:1.25rem;
      min-height:360px; max-height:540px; overflow-y:auto;
      white-space:pre-wrap; word-break:break-all;
    "></div>
    <div id="resultBox" class="mt-2" style="display:none"></div>
    <div class="mt-2">
      <a href="{{ url_for('test_page') }}" class="btn btn-outline-primary btn-sm me-2">Run Another Test</a>
      <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary btn-sm">Dashboard</a>
    </div>
  </div>

  <!-- Side panel -->
  <div class="col-lg-4">

    <!-- Callback health -->
    <div class="card p-3 mb-3">
      <h6 class="fw-bold mb-2">Callback Listener</h6>
      <div class="small text-muted mb-1">Local URL</div>
      <code class="small d-block mb-2" style="word-break:break-all">{{ cb_local }}</code>
      <div class="small text-muted mb-1">Public URL (sent to NGS)</div>
      <code class="small d-block mb-2" style="word-break:break-all">{{ cb_public }}</code>
      <div id="cbStatus" class="mt-1">
        <span class="badge bg-secondary">checking…</span>
      </div>
    </div>

    <!-- Simulate DLR -->
    <div class="card p-3" id="simulateCard">
      <h6 class="fw-bold mb-1">Simulate DLR</h6>
      <p class="text-muted small mb-3">
        Manually fire a fake NGS callback to the local listener.<br>
        Use this to test the full flow when the public callback URL
        is not yet reachable.
      </p>
      <div id="msgIdRow" class="mb-2 small text-muted" style="display:none">
        call_id: <code id="msgIdVal"></code>
      </div>
      <div class="d-grid gap-2" id="simBtns">
        <button class="btn btn-sm btn-success"   disabled onclick="simulate('delivrd')">
          &#10003; Simulate DELIVRD (answered)
        </button>
        <button class="btn btn-sm btn-warning"   disabled onclick="simulate('undeliv')">
          &#9888; Simulate UNDELIV (no answer)
        </button>
        <button class="btn btn-sm btn-secondary" disabled onclick="simulate('rejectd')">
          &#10005; Simulate REJECTD (cancelled)
        </button>
      </div>
      <div id="simResult" class="mt-2 small"></div>
    </div>

  </div>
</div>

<script>
const JOB_ID   = {{ job_id|tojson }};
const term     = document.getElementById('terminal');
const badge    = document.getElementById('statusBadge');
const resultBox= document.getElementById('resultBox');
const colours  = { info:'#c9d1d9', success:'#3fb950', warning:'#d29922', error:'#f85149' };
let   msgId    = null;

function appendLine(text, level) {
  const span = document.createElement('span');
  span.style.color = colours[level] || colours.info;
  span.textContent = text + '\\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}

// SSE stream
const es = new EventSource("{{ url_for('test_stream', job_id=job_id) }}");
es.onmessage = function(e) {
  const msg = JSON.parse(e.data);

  if (msg.level === 'msgid') {
    msgId = msg.message_id;
    document.getElementById('msgIdRow').style.display = '';
    document.getElementById('msgIdVal').textContent   = msgId;
    document.querySelectorAll('#simBtns button').forEach(b => b.disabled = false);
    return;
  }

  if (msg.level === 'done') {
    es.close();
    const ok = msg.success;
    badge.textContent = ok ? 'passed' : 'failed';
    badge.className   = 'badge ' + (ok ? 'bg-success' : 'bg-danger');
    resultBox.style.display = '';
    resultBox.innerHTML = ok
      ? '<div class="alert alert-success mb-0 py-2">&#10003; Test passed — DLR received.</div>'
      : '<div class="alert alert-danger  mb-0 py-2">&#10007; Test failed — see log above.</div>';
    return;
  }

  appendLine(msg.text, msg.level);
};
es.onerror = function() {
  es.close();
  appendLine('--- stream closed ---', 'warning');
  badge.textContent = 'disconnected';
  badge.className   = 'badge bg-warning text-dark';
};

// Simulate DLR
function simulate(stat) {
  const simRes = document.getElementById('simResult');
  simRes.innerHTML = '<span class="text-muted">Sending…</span>';
  fetch(`/test/simulate-dlr/${JOB_ID}/${stat}`, {method:'POST'})
    .then(r => r.json())
    .then(d => {
      if (d.ok) {
        simRes.innerHTML = '<span class="text-success">&#10003; Callback sent to ' +
          d.url + '</span>';
        appendLine(`[simulate] Sent ${stat.toUpperCase()} callback → ${d.url}`, 'warning');
      } else {
        simRes.innerHTML = '<span class="text-danger">&#10007; ' + d.error + '<br>' +
          'URL: ' + (d.url||'') + '</span>';
        appendLine(`[simulate] FAILED: ${d.error}`, 'error');
      }
    })
    .catch(err => {
      simRes.innerHTML = '<span class="text-danger">&#10007; ' + err + '</span>';
    });
}

// Callback listener health check
fetch('/test/callback-check')
  .then(r => r.json())
  .then(d => {
    const el = document.getElementById('cbStatus');
    if (d.reachable) {
      el.innerHTML = '<span class="badge bg-success">&#10003; listener reachable on port ' +
        d.port + '</span>';
    } else {
      el.innerHTML = '<span class="badge bg-danger">&#10007; port ' + d.port +
        ' not reachable — ' + d.error + '</span>' +
        '<div class="mt-1 text-danger small">smpp_server.py may not be running, ' +
        'or HTTP_LISTEN is not 0.0.0.0</div>';
    }
  });
</script>
{% endblock %}
"""


@app.route("/test")
@login_required
def test_page():
    users = query("SELECT system_id, credit_balance FROM users WHERE is_active=1 ORDER BY system_id")
    return render_template_string(TEST_FORM_TMPL,
                                  users=users,
                                  def_host=SMPP_DEF_HOST,
                                  def_port=SMPP_DEF_PORT)


@app.route("/test/run", methods=["POST"])
@login_required
def test_run():
    host    = request.form.get("host", SMPP_DEF_HOST).strip()
    port    = int(request.form.get("port") or SMPP_DEF_PORT)
    # prefer custom system_id over dropdown
    sid     = (request.form.get("system_id_custom") or "").strip() \
              or (request.form.get("system_id") or "").strip()
    pwd     = request.form.get("password", "")
    src     = request.form.get("src", "1000").strip()
    dst     = request.form.get("dst", "").strip()
    text    = request.form.get("text", "").strip()
    timeout = float(request.form.get("dlr_timeout")      or 60)
    interval= float(request.form.get("enquire_interval") or 10)
    req_dlr = "request_dlr" in request.form

    if not sid or not pwd or not dst or not text:
        flash("system_id, password, destination and text are required.", "error")
        return redirect(url_for("test_page"))

    job_id = str(uuid.uuid4())
    job    = {"q": queue.Queue(), "done": False, "success": False}
    with _test_jobs_lock:
        _test_jobs[job_id] = job

    t = threading.Thread(
        target=_smpp_test_runner,
        args=(job_id, host, port, sid, pwd, src, dst, text, timeout, interval, req_dlr),
        daemon=True,
    )
    t.start()

    return render_template_string(TEST_RESULT_TMPL, job_id=job_id,
                                  cb_local=HTTP_CALLBACK_LOCAL_URL,
                                  cb_public=NGS_STATUS_CALLBACK_URL)


@app.route("/test/stream/<job_id>")
@login_required
def test_stream(job_id):
    with _test_jobs_lock:
        job = _test_jobs.get(job_id)
    if not job:
        def _not_found():
            yield f"data: {json.dumps({'level':'error','text':'Job not found.'})}\n\n"
            yield f"data: {json.dumps({'level':'done','success':False})}\n\n"
        return Response(stream_with_context(_not_found()),
                        mimetype="text/event-stream")

    @stream_with_context
    def _generate():
        q = job["q"]
        while True:
            try:
                msg = q.get(timeout=1)
            except queue.Empty:
                # heartbeat so the connection stays alive
                yield ": heartbeat\n\n"
                continue
            yield f"data: {json.dumps(msg)}\n\n"
            if msg.get("level") == "done":
                break

    return Response(_generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Simulate DLR  — POST a fake NGS callback to the local HTTP listener
# ---------------------------------------------------------------------------
@app.route("/test/simulate-dlr/<job_id>/<stat>", methods=["POST"])
@login_required
def simulate_dlr(job_id, stat):
    """
    Fires a fake NextGenSwitch callback to the local HTTP listener so the
    SMPP server processes it and sends a DELIVER_SM to waiting clients.
    stat: delivrd | undeliv | rejectd
    """
    stat_map = {
        "delivrd": ("Disconnected", 3),
        "undeliv": ("NoAnswer",     5),
        "rejectd": ("Cancelled",    6),
    }
    if stat not in stat_map:
        return json.dumps({"ok": False, "error": "unknown stat"}), 400, \
               {"Content-Type": "application/json"}

    with _test_jobs_lock:
        job = _test_jobs.get(job_id)

    if not job:
        return json.dumps({"ok": False, "error": "job not found"}), 404, \
               {"Content-Type": "application/json"}

    msg_id = job.get("message_id", "")
    if not msg_id:
        return json.dumps({"ok": False, "error": "message_id not yet known"}), 400, \
               {"Content-Type": "application/json"}

    status_text, status_code = stat_map[stat]
    payload = json.dumps({
        "call_id":     msg_id,
        "status":      status_text,
        "status-code": status_code,
        "duration":    0,
    }).encode()

    try:
        req = urllib.request.Request(
            HTTP_CALLBACK_LOCAL_URL,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json",
                     "Content-Length": str(len(payload))},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
        return json.dumps({"ok": True, "response": body,
                           "url": HTTP_CALLBACK_LOCAL_URL,
                           "call_id": msg_id}), 200, \
               {"Content-Type": "application/json"}
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc),
                           "url": HTTP_CALLBACK_LOCAL_URL}), 502, \
               {"Content-Type": "application/json"}


@app.route("/test/callback-check")
@login_required
def callback_check():
    """Quick TCP reachability check on the local HTTP listener port."""
    try:
        s = _socket.create_connection(("127.0.0.1", _http_port), timeout=2)
        s.close()
        reachable = True
        error = ""
    except Exception as exc:
        reachable = False
        error = str(exc)

    return json.dumps({
        "local_url":    HTTP_CALLBACK_LOCAL_URL,
        "public_url":   NGS_STATUS_CALLBACK_URL,
        "port":         _http_port,
        "reachable":    reachable,
        "error":        error,
    }), 200, {"Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# SIP Accounts — list
# ---------------------------------------------------------------------------
SIP_TMPL = """\
{% extends 'base.html' %}
{% block title %}SIP Accounts{% endblock %}
{% block content %}
<div class="d-flex align-items-center justify-content-between mb-3">
  <h4 class="fw-bold mb-0">SIP Accounts (pjsip.conf)</h4>
  <div class="d-flex gap-2">
    <a href="{{ url_for('sip_transport') }}" class="btn btn-sm btn-outline-secondary">Transport Settings</a>
    <form method="post" action="{{ url_for('sip_reload') }}" class="mb-0">
      <button class="btn btn-sm btn-outline-warning">&#8635; Reload Asterisk</button>
    </form>
  </div>
</div>

<div class="card p-3 mb-4">
  <div class="d-flex flex-wrap gap-4 align-items-center">
    <div><span class="text-muted small">Bind</span><br><code>{{ transport.get('bind','0.0.0.0:5060') }}</code></div>
    <div><span class="text-muted small">External IP (signalling)</span><br>
      <code>{{ transport.get('external_signaling_address','—') }}</code></div>
    <div><span class="text-muted small">External IP (media)</span><br>
      <code>{{ transport.get('external_media_address','—') }}</code></div>
    <div class="ms-auto">
      <a href="{{ url_for('sip_transport') }}" class="btn btn-sm btn-outline-secondary">Edit Transport</a>
    </div>
  </div>
</div>

<div class="d-flex align-items-center justify-content-between mb-2">
  <h5 class="fw-bold mb-0">User Endpoints</h5>
  <a href="{{ url_for('sip_add_endpoint') }}" class="btn btn-sm btn-primary">+ Add Endpoint</a>
</div>
<div class="card mb-4">
  <div class="table-responsive">
    <table class="table table-hover align-middle mb-0">
      <thead class="table-dark">
        <tr><th>Name</th><th>Username</th><th>Password</th><th>Codecs</th><th>Permitted IP</th><th>Context</th><th></th></tr>
      </thead>
      <tbody>
        {% for ep in endpoints %}
        <tr>
          <td class="fw-semibold">{{ ep.name }}</td>
          <td>{{ ep.username }}</td>
          <td><code>{{ ep.password }}</code></td>
          <td><span class="badge bg-secondary">{{ ep.codecs }}</span></td>
          <td class="small">
            {% if ep.permit_ip %}
              <span class="badge bg-info text-dark">{{ ep.permit_ip }}</span>
            {% else %}
              <span class="text-muted">any</span>
            {% endif %}
          </td>
          <td class="text-muted small">{{ ep.context }}</td>
          <td class="text-end">
            <a href="{{ url_for('sip_edit_endpoint', name=ep.name) }}"
               class="btn btn-sm btn-outline-secondary me-1">Edit</a>
            <form method="post" action="{{ url_for('sip_delete_endpoint', name=ep.name) }}"
                  class="d-inline"
                  onsubmit="return confirm('Delete endpoint {{ ep.name }}?')">
              <button class="btn btn-sm btn-outline-danger">Delete</button>
            </form>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="text-center text-muted py-3">
          No endpoints. <a href="{{ url_for('sip_add_endpoint') }}">Add one.</a>
        </td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<div class="d-flex align-items-center justify-content-between mb-2">
  <h5 class="fw-bold mb-0">Trunks</h5>
  <a href="{{ url_for('sip_add_trunk') }}" class="btn btn-sm btn-primary">+ Add Trunk</a>
</div>
<div class="card">
  <div class="table-responsive">
    <table class="table table-hover align-middle mb-0">
      <thead class="table-dark">
        <tr><th>Name</th><th>Contact URI</th><th>Codecs</th><th>Qualify (s)</th><th>Context</th><th></th></tr>
      </thead>
      <tbody>
        {% for tr in trunks %}
        <tr>
          <td class="fw-semibold">{{ tr.name }}</td>
          <td><code>{{ tr.contact }}</code></td>
          <td><span class="badge bg-secondary">{{ tr.codecs }}</span></td>
          <td>{{ tr.qualify_frequency }}</td>
          <td class="text-muted small">{{ tr.context }}</td>
          <td class="text-end">
            <a href="{{ url_for('sip_edit_trunk', name=tr.name) }}"
               class="btn btn-sm btn-outline-secondary me-1">Edit</a>
            <form method="post" action="{{ url_for('sip_delete_trunk', name=tr.name) }}"
                  class="d-inline"
                  onsubmit="return confirm('Delete trunk {{ tr.name }}?')">
              <button class="btn btn-sm btn-outline-danger">Delete</button>
            </form>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="text-center text-muted py-3">
          No trunks. <a href="{{ url_for('sip_add_trunk') }}">Add one.</a>
        </td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""

SIP_ENDPOINT_FORM_TMPL = """\
{% extends 'base.html' %}
{% block title %}{{ 'Edit' if ep else 'Add' }} Endpoint{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <a href="{{ url_for('sip_accounts') }}" class="btn btn-sm btn-outline-secondary mb-3">&larr; Back</a>
    <div class="card p-4">
      <h5 class="fw-bold mb-3">{{ 'Edit' if ep else 'Add' }} User Endpoint</h5>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Name <span class="text-danger">*</span></label>
          <input name="name" class="form-control" value="{{ ep.name if ep else '' }}"
                 {% if ep %}readonly{% else %}required autofocus{% endif %} required>
          {% if ep %}<div class="form-text text-muted">Name cannot be changed.</div>{% endif %}
        </div>
        <div class="mb-3">
          <label class="form-label">Username</label>
          <input name="username" class="form-control"
                 value="{{ ep.username if ep else '' }}" placeholder="defaults to name">
        </div>
        <div class="mb-3">
          <label class="form-label">Password <span class="text-danger">*</span></label>
          <input type="text" name="password" class="form-control"
                 value="{{ ep.password if ep else '' }}" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Allowed Codecs</label>
          <input name="codecs" class="form-control"
                 value="{{ ep.codecs if ep else 'ulaw,alaw' }}" placeholder="ulaw,alaw">
          <div class="form-text">Comma-separated, e.g. <code>ulaw,alaw</code> or <code>g729</code></div>
        </div>
        <div class="mb-3">
          <label class="form-label">Context</label>
          <input name="context" class="form-control"
                 value="{{ ep.context if ep else 'from-users' }}">
        </div>
        <div class="mb-3">
          <label class="form-label">Direct Media</label>
          <select name="direct_media" class="form-select">
            <option value="no"  {{ 'selected' if (not ep) or ep.direct_media == 'no' }}>no</option>
            <option value="yes" {{ 'selected' if ep and ep.direct_media == 'yes' }}>yes</option>
          </select>
        </div>
        <div class="mb-4">
          <label class="form-label">Permitted IP <span class="text-muted fw-normal">(optional)</span></label>
          <input name="permit_ip" class="form-control"
                 value="{{ ep.permit_ip if ep else '' }}"
                 placeholder="leave blank to allow any IP">
          <div class="form-text">
            Restricts registration to this IP only. Accepts a single address, comma-separated
            list, or CIDR range (e.g. <code>192.168.1.100</code> or <code>10.0.0.0/24</code>).
          </div>
        </div>
        <button class="btn btn-primary w-100">{{ 'Save' if ep else 'Create Endpoint' }}</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""

SIP_TRUNK_FORM_TMPL = """\
{% extends 'base.html' %}
{% block title %}{{ 'Edit' if trunk else 'Add' }} Trunk{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <a href="{{ url_for('sip_accounts') }}" class="btn btn-sm btn-outline-secondary mb-3">&larr; Back</a>
    <div class="card p-4">
      <h5 class="fw-bold mb-3">{{ 'Edit' if trunk else 'Add' }} Trunk</h5>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Name <span class="text-danger">*</span></label>
          <input name="name" class="form-control" value="{{ trunk.name if trunk else '' }}"
                 {% if trunk %}readonly{% else %}required autofocus{% endif %} required>
          {% if trunk %}<div class="form-text text-muted">Name cannot be changed.</div>{% endif %}
        </div>
        <div class="mb-3">
          <label class="form-label">Contact URI <span class="text-danger">*</span></label>
          <input name="contact" class="form-control"
                 value="{{ trunk.contact if trunk else '' }}"
                 placeholder="sip:1.2.3.4:5060" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Allowed Codecs</label>
          <input name="codecs" class="form-control"
                 value="{{ trunk.codecs if trunk else 'g729' }}" placeholder="g729">
        </div>
        <div class="mb-3">
          <label class="form-label">Context</label>
          <input name="context" class="form-control"
                 value="{{ trunk.context if trunk else 'from-trunk' }}">
        </div>
        <div class="mb-4">
          <label class="form-label">Qualify Frequency (s)</label>
          <input type="number" name="qualify_frequency" class="form-control"
                 value="{{ trunk.qualify_frequency if trunk else '60' }}">
          <div class="form-text">Set to 0 to disable OPTIONS keepalives.</div>
        </div>
        <button class="btn btn-primary w-100">{{ 'Save' if trunk else 'Create Trunk' }}</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""

SIP_TRANSPORT_TMPL = """\
{% extends 'base.html' %}
{% block title %}Transport Settings{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <a href="{{ url_for('sip_accounts') }}" class="btn btn-sm btn-outline-secondary mb-3">&larr; Back</a>
    <div class="card p-4">
      <h5 class="fw-bold mb-3">Transport Settings</h5>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Bind Address</label>
          <input name="bind" class="form-control"
                 value="{{ transport.get('bind','0.0.0.0:5060') }}">
          <div class="form-text">e.g. <code>0.0.0.0:5060</code></div>
        </div>
        <div class="mb-3">
          <label class="form-label">External Signalling Address</label>
          <input name="external_signaling_address" class="form-control"
                 value="{{ transport.get('external_signaling_address','') }}"
                 placeholder="Your public IP">
        </div>
        <div class="mb-4">
          <label class="form-label">External Media Address</label>
          <input name="external_media_address" class="form-control"
                 value="{{ transport.get('external_media_address','') }}"
                 placeholder="Your public IP">
        </div>
        <button class="btn btn-primary w-100">Save Transport</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/sip")
@login_required
def sip_accounts():
    data = _pjsip_data()
    return render_template_string(SIP_TMPL,
                                  transport=data["transport"],
                                  endpoints=data["endpoints"],
                                  trunks=data["trunks"])


@app.route("/sip/add-endpoint", methods=["GET", "POST"])
@login_required
def sip_add_endpoint():
    if request.method == "POST":
        name         = request.form.get("name", "").strip()
        username     = request.form.get("username", "").strip() or name
        password     = request.form.get("password", "").strip()
        codecs       = request.form.get("codecs", "ulaw,alaw").strip()
        context      = request.form.get("context", "from-users").strip()
        direct_media = request.form.get("direct_media", "no")
        permit_ip    = request.form.get("permit_ip", "").strip()

        if not name or not password:
            flash("Name and password are required.", "error")
            return render_template_string(SIP_ENDPOINT_FORM_TMPL, ep=None)

        data = _pjsip_data()
        if any(e["name"] == name for e in data["endpoints"]):
            flash(f"Endpoint '{name}' already exists.", "error")
            return render_template_string(SIP_ENDPOINT_FORM_TMPL, ep=None)

        data["endpoints"].append({
            "name": name, "username": username, "password": password,
            "codecs": codecs, "context": context, "direct_media": direct_media,
            "permit_ip": permit_ip,
        })
        try:
            _pjsip_write(data)
            flash(f"Endpoint '{name}' created. Reload Asterisk to apply.", "success")
        except Exception as exc:
            flash(f"Write error: {exc}", "error")
        return redirect(url_for("sip_accounts"))

    return render_template_string(SIP_ENDPOINT_FORM_TMPL, ep=None)


@app.route("/sip/edit-endpoint/<name>", methods=["GET", "POST"])
@login_required
def sip_edit_endpoint(name):
    data = _pjsip_data()
    ep = next((e for e in data["endpoints"] if e["name"] == name), None)
    if not ep:
        flash(f"Endpoint '{name}' not found.", "error")
        return redirect(url_for("sip_accounts"))

    if request.method == "POST":
        ep["username"]     = request.form.get("username", "").strip() or name
        ep["password"]     = request.form.get("password", "").strip()
        ep["codecs"]       = request.form.get("codecs", "ulaw,alaw").strip()
        ep["context"]      = request.form.get("context", "from-users").strip()
        ep["direct_media"] = request.form.get("direct_media", "no")
        ep["permit_ip"]    = request.form.get("permit_ip", "").strip()

        if not ep["password"]:
            flash("Password cannot be empty.", "error")
            return render_template_string(SIP_ENDPOINT_FORM_TMPL, ep=ep)

        try:
            _pjsip_write(data)
            flash(f"Endpoint '{name}' saved. Reload Asterisk to apply.", "success")
        except Exception as exc:
            flash(f"Write error: {exc}", "error")
        return redirect(url_for("sip_accounts"))

    return render_template_string(SIP_ENDPOINT_FORM_TMPL, ep=ep)


@app.route("/sip/delete-endpoint/<name>", methods=["POST"])
@login_required
def sip_delete_endpoint(name):
    data = _pjsip_data()
    data["endpoints"] = [e for e in data["endpoints"] if e["name"] != name]
    try:
        _pjsip_write(data)
        flash(f"Endpoint '{name}' deleted. Reload Asterisk to apply.", "success")
    except Exception as exc:
        flash(f"Write error: {exc}", "error")
    return redirect(url_for("sip_accounts"))


@app.route("/sip/add-trunk", methods=["GET", "POST"])
@login_required
def sip_add_trunk():
    if request.method == "POST":
        name    = request.form.get("name", "").strip()
        contact = request.form.get("contact", "").strip()
        codecs  = request.form.get("codecs", "g729").strip()
        context = request.form.get("context", "from-trunk").strip()
        qualify = request.form.get("qualify_frequency", "60").strip()

        if not name or not contact:
            flash("Name and contact URI are required.", "error")
            return render_template_string(SIP_TRUNK_FORM_TMPL, trunk=None)

        data = _pjsip_data()
        if any(t["name"] == name for t in data["trunks"]):
            flash(f"Trunk '{name}' already exists.", "error")
            return render_template_string(SIP_TRUNK_FORM_TMPL, trunk=None)

        data["trunks"].append({
            "name": name, "contact": contact, "codecs": codecs,
            "context": context, "qualify_frequency": qualify,
        })
        try:
            _pjsip_write(data)
            flash(f"Trunk '{name}' created. Reload Asterisk to apply.", "success")
        except Exception as exc:
            flash(f"Write error: {exc}", "error")
        return redirect(url_for("sip_accounts"))

    return render_template_string(SIP_TRUNK_FORM_TMPL, trunk=None)


@app.route("/sip/edit-trunk/<name>", methods=["GET", "POST"])
@login_required
def sip_edit_trunk(name):
    data = _pjsip_data()
    trunk = next((t for t in data["trunks"] if t["name"] == name), None)
    if not trunk:
        flash(f"Trunk '{name}' not found.", "error")
        return redirect(url_for("sip_accounts"))

    if request.method == "POST":
        trunk["contact"]           = request.form.get("contact", "").strip()
        trunk["codecs"]            = request.form.get("codecs", "g729").strip()
        trunk["context"]           = request.form.get("context", "from-trunk").strip()
        trunk["qualify_frequency"] = request.form.get("qualify_frequency", "60").strip()

        if not trunk["contact"]:
            flash("Contact URI cannot be empty.", "error")
            return render_template_string(SIP_TRUNK_FORM_TMPL, trunk=trunk)

        try:
            _pjsip_write(data)
            flash(f"Trunk '{name}' saved. Reload Asterisk to apply.", "success")
        except Exception as exc:
            flash(f"Write error: {exc}", "error")
        return redirect(url_for("sip_accounts"))

    return render_template_string(SIP_TRUNK_FORM_TMPL, trunk=trunk)


@app.route("/sip/delete-trunk/<name>", methods=["POST"])
@login_required
def sip_delete_trunk(name):
    data = _pjsip_data()
    data["trunks"] = [t for t in data["trunks"] if t["name"] != name]
    try:
        _pjsip_write(data)
        flash(f"Trunk '{name}' deleted. Reload Asterisk to apply.", "success")
    except Exception as exc:
        flash(f"Write error: {exc}", "error")
    return redirect(url_for("sip_accounts"))


@app.route("/sip/transport", methods=["GET", "POST"])
@login_required
def sip_transport():
    data = _pjsip_data()
    if request.method == "POST":
        data["transport"]["bind"] = \
            request.form.get("bind", "0.0.0.0:5060").strip()
        data["transport"]["external_signaling_address"] = \
            request.form.get("external_signaling_address", "").strip()
        data["transport"]["external_media_address"] = \
            request.form.get("external_media_address", "").strip()
        try:
            _pjsip_write(data)
            flash("Transport settings saved. Reload Asterisk to apply.", "success")
        except Exception as exc:
            flash(f"Write error: {exc}", "error")
        return redirect(url_for("sip_accounts"))

    return render_template_string(SIP_TRANSPORT_TMPL, transport=data["transport"])


@app.route("/sip/reload", methods=["POST"])
@login_required
def sip_reload():
    try:
        result = subprocess.run(
            ["docker", "exec", _docker_cfg_read()["container"], "asterisk", "-rx", "pjsip reload"],
            capture_output=True, text=True, timeout=10,
        )
        out = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            flash(f"Asterisk reloaded. {out}", "success")
        else:
            flash(f"Reload failed (rc={result.returncode}): {out}", "error")
    except Exception as exc:
        flash(f"Reload error: {exc}", "error")
    return redirect(url_for("sip_accounts"))


# ---------------------------------------------------------------------------
# SMPP service management
# ---------------------------------------------------------------------------
SMPP_TMPL = """\
{% extends 'base.html' %}
{% block title %}SMPP Service{% endblock %}
{% block content %}
<div class="d-flex align-items-center justify-content-between mb-3">
  <h4 class="fw-bold mb-0">SMPP Server</h4>
  <div class="d-flex align-items-center gap-2">
    {% if status == 'running' %}
      <span class="badge bg-success" style="font-size:.9rem">&#9679; running &nbsp;pid&nbsp;{{ pid }}</span>
    {% else %}
      <span class="badge bg-secondary" style="font-size:.9rem">&#9679; stopped</span>
    {% endif %}
    <a href="{{ url_for('smpp_page') }}" class="btn btn-sm btn-outline-secondary">&#8635; Refresh</a>
  </div>
</div>

<div class="card p-3 mb-4">
  <div class="d-flex flex-wrap gap-2">
    <form method="post" action="{{ url_for('smpp_start') }}" class="mb-0">
      <button class="btn btn-success px-4" {{ 'disabled' if status == 'running' }}>&#9654; Start</button>
    </form>
    <form method="post" action="{{ url_for('smpp_stop') }}" class="mb-0">
      <button class="btn btn-danger px-4" {{ 'disabled' if status != 'running' }}>&#9632; Stop</button>
    </form>
    <form method="post" action="{{ url_for('smpp_restart') }}" class="mb-0">
      <button class="btn btn-warning px-4" {{ 'disabled' if status != 'running' }}>&#8635; Restart</button>
    </form>
  </div>
</div>

<div class="row g-4">

  <div class="col-lg-5">
    <div class="card p-4">
      <h5 class="fw-bold mb-3">Configuration <span class="text-muted fw-normal small">(.env)</span></h5>
      <form method="post" action="{{ url_for('smpp_save_env') }}">
        {% for group_name, fields in groups %}
        <h6 class="text-muted mb-2 {{ 'mt-3' if not loop.first else '' }}">{{ group_name }}</h6>
        {% for key, label, ftype in fields %}
        <div class="mb-2">
          <label class="form-label mb-1 small fw-semibold">{{ label }}</label>
          {% if ftype == 'number' %}
            <input type="number" name="{{ key }}" class="form-control form-control-sm"
                   value="{{ env.get(key, '') }}">
          {% elif ftype.startswith('select:') %}
            <select name="{{ key }}" class="form-select form-select-sm">
              {% for opt in ftype[7:].split(',') %}
              <option value="{{ opt }}" {{ 'selected' if env.get(key,'') == opt }}>{{ opt }}</option>
              {% endfor %}
            </select>
          {% else %}
            <input name="{{ key }}" class="form-control form-control-sm"
                   value="{{ env.get(key, '') }}">
          {% endif %}
        </div>
        {% endfor %}
        {% endfor %}
        <button class="btn btn-primary w-100 mt-3">Save Configuration</button>
        <div class="form-text text-center mt-1">Restart the server after saving to apply changes.</div>
      </form>
    </div>
  </div>

  <div class="col-lg-7">
    <div class="card p-3">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <h5 class="fw-bold mb-0">Live Log</h5>
        <button type="button" class="btn btn-sm btn-outline-secondary"
                onclick="document.getElementById('logterm').textContent=''">Clear</button>
      </div>
      <div id="logterm" style="
        background:#0d1117; color:#c9d1d9; font-family:monospace;
        font-size:.8rem; border-radius:8px; padding:1rem;
        height:500px; overflow-y:auto; white-space:pre-wrap; word-break:break-all;
      "></div>
    </div>
  </div>

</div>

<script>
const term = document.getElementById('logterm');
const levelColor = { ERROR:'#f85149', WARNING:'#d29922', INFO:'#c9d1d9', DEBUG:'#8b949e' };

function appendLine(raw) {
  let color = '#c9d1d9';
  for (const [k, v] of Object.entries(levelColor)) {
    if (raw.includes(k)) { color = v; break; }
  }
  const span = document.createElement('span');
  span.style.color = color;
  span.textContent = raw + '\\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}

const es = new EventSource("{{ url_for('smpp_log_stream') }}");
es.onmessage = e => appendLine(JSON.parse(e.data));
es.onerror   = () => appendLine('--- stream disconnected ---');
</script>
{% endblock %}
"""


@app.route("/smpp")
@login_required
def smpp_page():
    status, pid = _smpp_status()
    return render_template_string(SMPP_TMPL,
                                  status=status, pid=pid,
                                  groups=_SMPP_CONFIG_GROUPS,
                                  env=_env_read())


@app.route("/smpp/start", methods=["POST"])
@login_required
def smpp_start():
    ok, msg = _smpp_start()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("smpp_page"))


@app.route("/smpp/stop", methods=["POST"])
@login_required
def smpp_stop():
    ok, msg = _smpp_stop()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("smpp_page"))


@app.route("/smpp/restart", methods=["POST"])
@login_required
def smpp_restart():
    _smpp_stop()
    time.sleep(0.5)
    ok, msg = _smpp_start()
    flash(msg, "success" if ok else "error")
    return redirect(url_for("smpp_page"))


@app.route("/smpp/save-env", methods=["POST"])
@login_required
def smpp_save_env():
    all_keys = [k for _, fields in _SMPP_CONFIG_GROUPS for k, _, _ in fields]
    updates  = {k: request.form.get(k, "").strip() for k in all_keys
                if request.form.get(k) is not None}
    try:
        _env_write(updates)
        flash("Configuration saved. Restart the server to apply.", "success")
    except Exception as exc:
        flash(f"Save error: {exc}", "error")
    return redirect(url_for("smpp_page"))


@app.route("/smpp/log-stream")
@login_required
def smpp_log_stream():
    @stream_with_context
    def generate():
        try:
            with open(SMPP_LOG_FILE, encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - 32768))
                f.readline()  # skip partial first line
                for line in f:
                    yield f"data: {json.dumps(line.rstrip())}\n\n"
                while True:
                    line = f.readline()
                    if line:
                        yield f"data: {json.dumps(line.rstrip())}\n\n"
                    else:
                        time.sleep(0.3)
                        yield ": heartbeat\n\n"
        except FileNotFoundError:
            yield f"data: {json.dumps('(log file not found — start the server first)')}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Docker management
# ---------------------------------------------------------------------------
DOCKER_TMPL = """\
{% extends 'base.html' %}
{% block title %}Docker — Asterisk{% endblock %}
{% block content %}
<div class="d-flex align-items-center justify-content-between mb-3">
  <h4 class="fw-bold mb-0">Asterisk Docker</h4>
  <div class="d-flex align-items-center gap-2">
    {% if status == 'running' %}
      <span class="badge bg-success" style="font-size:.95rem">&#9679; running</span>
    {% elif status in ('exited', 'created', 'paused') %}
      <span class="badge bg-secondary" style="font-size:.95rem">&#9679; {{ status }}</span>
    {% else %}
      <span class="badge bg-danger" style="font-size:.95rem">&#9679; {{ status }}</span>
    {% endif %}
    <a href="{{ url_for('docker_page') }}" class="btn btn-sm btn-outline-secondary">&#8635; Refresh</a>
  </div>
</div>

<div class="card p-3 mb-4">
  <div class="d-flex flex-wrap gap-2">
    <form method="post" action="{{ url_for('docker_start') }}" class="mb-0">
      <button class="btn btn-success px-4"
              {{ 'disabled' if status == 'running' }}>&#9654; Start</button>
    </form>
    <form method="post" action="{{ url_for('docker_stop') }}" class="mb-0">
      <button class="btn btn-danger px-4"
              {{ 'disabled' if status != 'running' }}>&#9632; Stop</button>
    </form>
    <form method="post" action="{{ url_for('docker_restart') }}" class="mb-0">
      <button class="btn btn-warning px-4"
              {{ 'disabled' if status != 'running' }}>&#8635; Restart</button>
    </form>
  </div>
</div>

<div class="row g-4">
  <div class="col-lg-6">
    <div class="card p-4">
      <h5 class="fw-bold mb-3">Run Configuration</h5>
      <form method="post" action="{{ url_for('docker_save') }}">
        <div class="row mb-3">
          <div class="col">
            <label class="form-label">Docker Image</label>
            <input name="image" class="form-control" value="{{ cfg.image }}">
          </div>
          <div class="col">
            <label class="form-label">Container Name</label>
            <input name="container" class="form-control" value="{{ cfg.container }}">
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">Bind IP</label>
          <input name="bind_ip" class="form-control" value="{{ cfg.bind_ip }}"
                 placeholder="57.128.20.2">
          <div class="form-text">IP address to bind SIP and RTP ports to on the host.</div>
        </div>
        <div class="row mb-4">
          <div class="col">
            <label class="form-label">SIP Port</label>
            <input type="number" name="sip_port" class="form-control" value="{{ cfg.sip_port }}">
          </div>
          <div class="col">
            <label class="form-label">RTP Start</label>
            <input type="number" name="rtp_start" class="form-control" value="{{ cfg.rtp_start }}">
          </div>
          <div class="col">
            <label class="form-label">RTP End</label>
            <input type="number" name="rtp_end" class="form-control" value="{{ cfg.rtp_end }}">
          </div>
        </div>
        <button class="btn btn-primary w-100">Save Configuration</button>
      </form>
    </div>
  </div>

  <div class="col-lg-6">
    <div class="card p-4">
      <h5 class="fw-bold mb-3">Generated Command</h5>
      <pre class="p-3 small mb-2" style="background:#1e1e2e;color:#cdd6f4;border-radius:8px;
           white-space:pre-wrap;word-break:break-all">{{ cmd }}</pre>
      <p class="text-muted small mb-0">
        Volumes mounted from <code>{{ transcoder_dir }}</code>
      </p>
    </div>
  </div>
</div>
{% endblock %}
"""


@app.route("/docker")
@login_required
def docker_page():
    cfg    = _docker_cfg_read()
    status = _docker_status(cfg["container"])
    return render_template_string(DOCKER_TMPL,
                                  cfg=type("C", (), cfg)(),
                                  status=status,
                                  cmd=_docker_run_cmd_str(cfg),
                                  transcoder_dir=_docker_transcoder_dir())


@app.route("/docker/save", methods=["POST"])
@login_required
def docker_save():
    cfg = {
        "image":     request.form.get("image",     "").strip() or _DOCKER_DEFAULTS["image"],
        "container": request.form.get("container", "").strip() or _DOCKER_DEFAULTS["container"],
        "bind_ip":   request.form.get("bind_ip",   "").strip() or _DOCKER_DEFAULTS["bind_ip"],
        "sip_port":  request.form.get("sip_port",  "5060").strip(),
        "rtp_start": request.form.get("rtp_start", "10000").strip(),
        "rtp_end":   request.form.get("rtp_end",   "10100").strip(),
    }
    try:
        _docker_cfg_write(cfg)
        flash("Docker configuration saved.", "success")
    except Exception as exc:
        flash(f"Save error: {exc}", "error")
    return redirect(url_for("docker_page"))


@app.route("/docker/start", methods=["POST"])
@login_required
def docker_start():
    cfg    = _docker_cfg_read()
    status = _docker_status(cfg["container"])
    try:
        if status in ("exited", "created", "paused"):
            args = ["docker", "start", cfg["container"]]
        else:
            args = _docker_run_args(cfg)
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        out = (r.stdout + r.stderr).strip()
        if r.returncode == 0:
            flash(f"Container started. {out}", "success")
        else:
            flash(f"Start failed: {out}", "error")
    except Exception as exc:
        flash(f"Start error: {exc}", "error")
    return redirect(url_for("docker_page"))


@app.route("/docker/stop", methods=["POST"])
@login_required
def docker_stop():
    cfg = _docker_cfg_read()
    try:
        r = subprocess.run(["docker", "stop", cfg["container"]],
                           capture_output=True, text=True, timeout=30)
        out = (r.stdout + r.stderr).strip()
        if r.returncode == 0:
            flash(f"Container stopped. {out}", "success")
        else:
            flash(f"Stop failed: {out}", "error")
    except Exception as exc:
        flash(f"Stop error: {exc}", "error")
    return redirect(url_for("docker_page"))


@app.route("/docker/restart", methods=["POST"])
@login_required
def docker_restart():
    cfg = _docker_cfg_read()
    try:
        r = subprocess.run(["docker", "restart", cfg["container"]],
                           capture_output=True, text=True, timeout=30)
        out = (r.stdout + r.stderr).strip()
        if r.returncode == 0:
            flash(f"Container restarted. {out}", "success")
        else:
            flash(f"Restart failed: {out}", "error")
    except Exception as exc:
        flash(f"Restart error: {exc}", "error")
    return redirect(url_for("docker_page"))


# ---------------------------------------------------------------------------
# Register base.html with Jinja2 so {% extends 'base.html' %} works
# ---------------------------------------------------------------------------
app.jinja_loader = ChoiceLoader([
    DictLoader({"base.html": BASE}),
    app.jinja_loader,
])


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SMPP billing web admin")
    ap.add_argument("--host",  default=WEB_HOST)
    ap.add_argument("--port",  type=int, default=WEB_PORT)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    if not Path(DB_PATH).exists():
        print(f"WARNING: DB not found at {DB_PATH!r}. "
              "Start smpp_server.py first or set DB_PATH in .env")

    print(f"Billing web admin  →  http://{args.host}:{args.port}")
    print(f"DB: {DB_PATH}  |  Password: WEB_PASSWORD in .env")
    app.run(host=args.host, port=args.port, debug=args.debug,
            threaded=True)
