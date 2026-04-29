# Asterisk G.729 Transcoder

Asterisk 15 container that transcodes between G.729 (trunk) and ulaw/alaw (endpoints). Built on Debian Buster Slim with the binary G.729 codec from `asterisk.hosting.lv`.

## Requirements

- Docker or Podman
- Host IP: `57.128.20.2` (update `pjsip.conf` and run commands if different)

## Directory layout

```
.
├── Dockerfile
├── config/
│   ├── extensions.conf
│   ├── modules.conf
│   ├── pjsip.conf
│   └── rtp.conf
├── logs/
├── lib/
└── spool/
```

## Build

```bash
docker build -t asterisk15-g729 .
```

To build a specific Asterisk version:

```bash
docker build --build-arg ASTERISK_VERSION=15.7.0 -t asterisk15-g729 .
```

## Start

```bash
docker run -d \
  --name asterisk15-g729 \
  --restart unless-stopped \
  -p 57.128.20.2:5060:5060/udp \
  -p 57.128.20.2:10000-10100:10000-10100/udp \
  -v $(pwd)/config:/etc/asterisk \
  -v $(pwd)/logs:/var/log/asterisk \
  -v $(pwd)/spool:/var/spool/asterisk \
  asterisk15-g729
```

> **Podman users:** append `:Z` to each `-v` volume flag (SELinux relabelling).

## Stop

```bash
docker stop asterisk15-g729
```

## Remove container

```bash
docker rm asterisk15-g729
```

## Restart

```bash
docker restart asterisk15-g729
```

## Asterisk CLI

```bash
docker exec -it asterisk15-g729 asterisk -rvvv
```

Useful CLI commands once inside:

```
core show channels          # active calls
pjsip show endpoints        # endpoint status
pjsip show registrations    # registration status
core reload                 # reload config without restart
```

## Logs

```bash
# Live log stream
docker logs -f asterisk15-g729

# Or read the mounted log file directly
tail -f logs/asterisk/full
```

## Configuration

| File | Purpose |
|------|---------|
| `config/pjsip.conf` | SIP transport, endpoints, trunk |
| `config/extensions.conf` | Dialplan — routes calls to trunk |
| `config/rtp.conf` | RTP port range (10000–10100) |
| `config/modules.conf` | Module autoload settings |

### Changing the public IP

Edit `config/pjsip.conf` and update both `external_signaling_address` and `external_media_address`, then update the `-p` bind addresses in the `docker run` command.

### Exposed ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 5060 | UDP | SIP signalling |
| 10000–10100 | UDP | RTP media |
