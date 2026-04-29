# SMPP Voice OTP Server

An SMPP 3.4 server that converts incoming `SUBMIT_SM` messages into outbound
voice calls via the **NextGenSwitch Programmable Voice API**, with full
**SQLite billing**, **per-user authentication**, and a **web admin panel**.

---

## How It Works

```
SMPP Client  →  smpp_server.py  →  NextGenSwitch API  →  Phone call
                     │
                     │  (statusCallback)
                     ↓
              HTTP callback (port 8080)
                     │
                     ↓
              DELIVER_SM (DLR) back to SMPP client
```

1. An SMPP client binds with a `system_id` / `password`.
2. On `SUBMIT_SM`, the server calls NextGenSwitch to place a voice call that
   reads the SMS text aloud (TTS-formatted for OTP codes).
3. NextGenSwitch sends a status callback to the HTTP listener.
4. The server maps the call status to an SMPP delivery receipt and sends it
   back to the client.
5. Every message is recorded in SQLite; credit is deducted atomically.

---

## Files

| File | Purpose |
|---|---|
| `smpp_server.py` | SMPP server + billing engine |
| `billing_web.py` | Web admin panel (Flask) |
| `.env` | All configuration (auto-loaded by both scripts) |
| `whitelist.txt` | Optional IP allowlist (one IP or CIDR per line) |
| `smpp.db` | SQLite database (created on first run) |
| `smpp.csv` | CSV event log (created on first run) |

---

## Requirements

- **Python 3.7+** (tested on 3.11 — use `python3.11` on CentOS/RHEL)
- **Flask** (for the web admin only)

```bash
pip3.11 install flask
```

No other third-party packages are needed. The SMPP server itself uses only
the Python standard library.

---

## Configuration — `.env`

Both `smpp_server.py` and `billing_web.py` auto-load `.env` from the same
directory at startup. Environment variables already set in the shell always
take priority over `.env` values.

```ini
# ── SMPP Server ──────────────────────────────────────────────
SMPP_LISTEN=0.0.0.0:2775        # IP:port for SMPP (use specific IP to restrict)
HTTP_LISTEN=0.0.0.0:8080        # IP:port for the NGS status-callback listener
HTTP_PATH=/ngs/status           # URL path for the status callback

# ── IP Allowlist (optional) ───────────────────────────────────
IP_WHITELIST_FILE=./whitelist.txt  # Remove line to disable

# ── NextGenSwitch API ─────────────────────────────────────────
NGS_BASE_URL=https://your.nextgenswitch.com
NGS_AUTH_CODE=<your-auth-code>
NGS_AUTH_SECRET=<your-auth-secret>
NGS_STATUS_CALLBACK=http://<this-server-public-ip>:8080/ngs/status
NGS_TIMEOUT=8                   # HTTP timeout in seconds
NGS_DEFAULT_FROM=               # Optional fixed caller-ID for all calls

# ── Database & Logging ────────────────────────────────────────
DB_PATH=./smpp.db
CSV_LOG=./smpp.csv
LOG_LEVEL=INFO                  # DEBUG | INFO | WARNING | ERROR
DLR_INTERMEDIATE=false          # true = also send receipt at call-answered stage

# ── Web Admin ─────────────────────────────────────────────────
WEB_HOST=0.0.0.0                # Bind address for the web panel
WEB_PORT=8888
WEB_PASSWORD=changeme           # ← CHANGE THIS
WEB_SECRET_KEY=changeme-secret  # ← CHANGE THIS (any random string)
```

> **Important:** `NGS_STATUS_CALLBACK` must be a URL that NextGenSwitch can
> reach from the internet. If both services run on the same host you can use
> `http://127.0.0.1:8080/ngs/status`; otherwise use the server's public IP.

---

## First-Time Setup

### 1. Clone / copy files

```bash
cd /opt/smpp        # or wherever you placed the files
```

### 2. Edit `.env`

Fill in your NextGenSwitch credentials and choose a strong
`WEB_PASSWORD` / `WEB_SECRET_KEY`.

### 3. Create the database and first user

```bash
python3.11 smpp_server.py --db ./smpp.db --manage add-user \
    --system-id myuser --password mypassword \
    --credit 100.0 --rate 0.05
```

### 4. (Optional) Populate the IP whitelist

```
# whitelist.txt — one entry per line, comments with #
203.0.113.10
198.51.100.0/24
```

Leave the file empty or remove `IP_WHITELIST_FILE` from `.env` to allow
connections from any IP.

---

## Running the SMPP Server

```bash
python3.11 smpp_server.py
```

All settings are read from `.env`. You can override any value on the
command line:

```bash
python3.11 smpp_server.py --log-level DEBUG
python3.11 smpp_server.py --listen 0.0.0.0:2775 --ngs-default-from +12025550100
```

### Run as a background service (systemd)

Create `/etc/systemd/system/smpp.service`:

```ini
[Unit]
Description=SMPP Voice OTP Server
After=network.target

[Service]
WorkingDirectory=/opt/smpp
ExecStart=/usr/local/bin/python3.11 smpp_server.py
Restart=always
RestartSec=5
User=smpp

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now smpp
systemctl status smpp
journalctl -fu smpp
```

---

## Running the Web Admin

```bash
python3.11 billing_web.py
```

Open `http://<server-ip>:8888` in your browser and log in with `WEB_PASSWORD`.

Override host/port if needed:

```bash
python3.11 billing_web.py --host 127.0.0.1 --port 9000
```

### Run as a background service (systemd)

```ini
[Unit]
Description=SMPP Billing Web Admin
After=network.target

[Service]
WorkingDirectory=/opt/smpp
ExecStart=/usr/local/bin/python3.11 billing_web.py
Restart=always
RestartSec=5
User=smpp

[Install]
WantedBy=multi-user.target
```

---

## User Management (CLI)

All management commands require `--db` (or `DB_PATH` in `.env`). They run
synchronously and exit immediately — the server does not need to be running.

### Add a user

```bash
python3.11 smpp_server.py --manage add-user \
    --system-id alice \
    --password secret \
    --credit 50.0 \
    --rate 0.05 \
    --notes "Client A"
```

| Field | Meaning |
|---|---|
| `system_id` | The SMPP username the client uses to bind |
| `password` | SMPP bind password (PBKDF2-SHA256 hashed in DB) |
| `credit` | Starting balance |
| `rate` | Cost deducted per successful call |

### List all users

```bash
python3.11 smpp_server.py --manage list-users
```

```
ID    system_id            active       balance       rate  created_at
------------------------------------------------------------------------
1     alice                yes          50.0000     0.0500  2026-04-28T06:00
2     bob                  no            0.0000     0.1000  2026-04-28T07:00
```

### Top up credit

```bash
python3.11 smpp_server.py --manage topup \
    --system-id alice --amount 100.0
```

### View a user report

```bash
python3.11 smpp_server.py --manage report --system-id alice
# Omit --system-id for a summary of all users
python3.11 smpp_server.py --manage report
```

### Change password

```bash
python3.11 smpp_server.py --manage passwd \
    --system-id alice --password newpassword
```

### Enable / disable a user

```bash
python3.11 smpp_server.py --manage set-active --system-id alice --active 0
python3.11 smpp_server.py --manage set-active --system-id alice --active 1
```

### Change rate per SMS

```bash
python3.11 smpp_server.py --manage set-rate --system-id alice --rate 0.10
```

---

## Web Admin Panel

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | All users — balance, messages, revenue |
| User detail | `/user/<id>` | Stats, last 20 ledger entries and messages |
| Add user | `/add-user` | Create a new SMPP user |
| Top up | `/topup/<id>` | Add credit |
| Edit user | `/edit/<id>` | Rate, active status, password |
| Sessions | `/sessions` | Last 100 SMPP bind sessions (live/ended) |

Balances shown **in red** on the dashboard mean the user has insufficient
credit for their next call.

---

## Billing Logic

1. **At BIND** — credentials are checked against the `users` table
   (PBKDF2-SHA256). An inactive user is rejected.

2. **At SUBMIT_SM** — if `rate_per_sms > 0`, the server reads the live
   balance. If `balance < rate`, it responds with `ESME_RSUBMITFAIL` and
   does **not** place the call.

3. **After the NGS call** — one `messages` row is written and the credit
   is deducted with a single atomic SQL statement:
   ```sql
   UPDATE users SET credit_balance = credit_balance - ?
   WHERE id = ? AND credit_balance >= ?
   ```
   This prevents double-charging under concurrent sessions.

4. **A failed NGS call** is recorded but **not charged** (`charge = 0`).

5. **At DLR final** — the `messages` row is updated with `dlr_stat` and
   `dlr_ts` for auditing.

---

## Database Schema

```
users           — credentials, balance, rate, is_active
sessions        — one row per SMPP BIND, closed on disconnect
messages        — one row per SUBMIT_SM (call_id, charge, dlr_stat)
billing_ledger  — append-only: every charge and topup with balance_after
```

Inspect directly:

```bash
sqlite3 smpp.db
sqlite> SELECT system_id, credit_balance, rate_per_sms FROM users;
sqlite> SELECT * FROM billing_ledger ORDER BY id DESC LIMIT 10;
sqlite> SELECT * FROM messages ORDER BY id DESC LIMIT 20;
```

---

## Authentication Modes

| `--db` set | `--password` set | Behaviour |
|---|---|---|
| Yes | — | DB auth (per-user passwords) |
| No | Yes | Single fixed password for all clients |
| No | No | Accept any password (open — dev only) |

---

## Delivery Receipt Mapping

| NGS `status-code` | SMPP `stat` | Final? |
|---|---|---|
| -1 / 0 / 1 | `ENROUTE` | No |
| 2 (Established) | `ACCEPTD` | No (intermediate, if `DLR_INTERMEDIATE=true`) |
| 3 (Disconnected) | `DELIVRD` | Yes |
| 4 (Busy) | `UNDELIV` | Yes |
| 5 (NoAnswer) | `UNDELIV` | Yes |
| 6 (Cancelled) | `REJECTD` | Yes |
| 7 (Failed) | `UNDELIV` | Yes |

---

## Troubleshooting

**BIND rejected — `ESME_RINVPASWD`**
- Check `system_id` and `password` match what was created with `add-user`.
- Verify the user is active: `--manage list-users`.

**BIND rejected — `ESME_RBINDFAIL`**
- The client IP is not in `whitelist.txt`. Add it or remove
  `IP_WHITELIST_FILE` from `.env`.

**`ESME_RSUBMITFAIL` on every message**
- Check balance: `--manage report --system-id <id>`.
- Top up with `--manage topup`.

**No DLR received**
- `NGS_STATUS_CALLBACK` must be reachable by NextGenSwitch from the internet.
  Test with: `curl -X POST http://<your-ip>:8080/ngs/status -d '{}'`
- Check `LOG_LEVEL=DEBUG` output for `[CB]` lines.

**Web admin shows "DB not found"**
- Start `smpp_server.py` at least once first (it creates the schema), or
  run any `--manage` command.

**`No module named 'dataclasses'` error**
- You are running Python 3.6. Use `python3.11` (installed at
  `/usr/local/bin/python3.11` on this server).
