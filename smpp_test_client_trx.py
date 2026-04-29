#!/usr/bin/env python3
import socket
import struct
import argparse
import sys
import time

# SMPP 3.4 command IDs
BIND_TRANSCEIVER      = 0x00000009
BIND_TRANSCEIVER_RESP = 0x80000009

SUBMIT_SM             = 0x00000004
SUBMIT_SM_RESP        = 0x80000004

DELIVER_SM            = 0x00000005
DELIVER_SM_RESP       = 0x80000005

ENQUIRE_LINK          = 0x00000015
ENQUIRE_LINK_RESP     = 0x80000015

UNBIND                = 0x00000006
UNBIND_RESP           = 0x80000006

ESME_ROK = 0x00000000

HDR_FMT = ">IIII"
HDR_LEN = 16


def cstr(s: str) -> bytes:
    return s.encode("utf-8", errors="replace") + b"\x00"


def build_pdu(cmd_id: int, status: int, seq: int, body: bytes = b"") -> bytes:
    length = HDR_LEN + len(body)
    return struct.pack(HDR_FMT, length, cmd_id, status, seq) + body


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data += chunk
    return data


def recv_pdu(sock: socket.socket):
    hdr = recv_exact(sock, 4)
    (pdu_len,) = struct.unpack(">I", hdr)
    rest = recv_exact(sock, pdu_len - 4)
    pdu = hdr + rest
    length, cmd_id, status, seq = struct.unpack(HDR_FMT, pdu[:HDR_LEN])
    body = pdu[HDR_LEN:]
    return length, cmd_id, status, seq, body


def read_cstring(buf: bytes, offset: int):
    end = buf.find(b"\x00", offset)
    if end == -1:
        return "", len(buf)
    return buf[offset:end].decode("utf-8", errors="replace"), end + 1


def bind_transceiver(sock: socket.socket, system_id: str, password: str, system_type: str, seq: int):
    # bind_transceiver body:
    # system_id, password, system_type (cstring)
    # interface_version (1)
    # addr_ton (1), addr_npi (1)
    # address_range (cstring)
    body = (
        cstr(system_id) +
        cstr(password) +
        cstr(system_type) +
        bytes([0x34]) +            # interface_version = 0x34 (SMPP 3.4)
        bytes([0x00]) +            # addr_ton
        bytes([0x00]) +            # addr_npi
        cstr("")                   # address_range
    )
    pdu = build_pdu(BIND_TRANSCEIVER, 0, seq, body)
    sock.sendall(pdu)

    _, cmd_id, status, rseq, rbody = recv_pdu(sock)
    if cmd_id != BIND_TRANSCEIVER_RESP:
        raise RuntimeError(f"Expected BIND_TRANSCEIVER_RESP, got 0x{cmd_id:08x}")
    return status, rseq, rbody


def submit_sm(sock: socket.socket, src: str, dst: str, text: str, seq: int,
              src_ton=0x00, src_npi=0x00, dst_ton=0x00, dst_npi=0x00,
              data_coding=0x00, request_dlr=True):
    # submit_sm body (minimal, no TLVs):
    # ...
    # registered_delivery (1)  <-- set to 0x01 to request final DLR
    msg_bytes = text.encode("utf-8", errors="replace")
    if len(msg_bytes) > 254:
        raise ValueError("short_message too long for this simple script (max 254 bytes)")

    registered_delivery = 0x01 if request_dlr else 0x00

    body = (
        cstr("") +
        bytes([src_ton, src_npi]) + cstr(src) +
        bytes([dst_ton, dst_npi]) + cstr(dst) +
        bytes([0x00, 0x00, 0x00]) +    # esm_class, protocol_id, priority_flag
        cstr("") +                     # schedule_delivery_time
        cstr("") +                     # validity_period
        bytes([registered_delivery]) + # registered_delivery
        bytes([0x00]) +                # replace_if_present_flag
        bytes([data_coding]) +         # data_coding
        bytes([0x00]) +                # sm_default_msg_id
        bytes([len(msg_bytes)]) + msg_bytes
    )
    pdu = build_pdu(SUBMIT_SM, 0, seq, body)
    sock.sendall(pdu)

    _, cmd_id, status, rseq, rbody = recv_pdu(sock)
    if cmd_id != SUBMIT_SM_RESP:
        raise RuntimeError(f"Expected SUBMIT_SM_RESP, got 0x{cmd_id:08x}")

    msg_id = ""
    if rbody:
        msg_id = rbody.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return status, rseq, msg_id


def enquire_link(sock: socket.socket, seq: int):
    pdu = build_pdu(ENQUIRE_LINK, 0, seq)
    sock.sendall(pdu)
    _, cmd_id, status, rseq, _ = recv_pdu(sock)
    if cmd_id != ENQUIRE_LINK_RESP:
        raise RuntimeError(f"Expected ENQUIRE_LINK_RESP, got 0x{cmd_id:08x}")
    return status, rseq


def unbind(sock: socket.socket, seq: int):
    pdu = build_pdu(UNBIND, 0, seq)
    sock.sendall(pdu)
    _, cmd_id, status, rseq, _ = recv_pdu(sock)
    if cmd_id != UNBIND_RESP:
        raise RuntimeError(f"Expected UNBIND_RESP, got 0x{cmd_id:08x}")
    return status, rseq


def parse_deliver_sm(body: bytes):
    """
    Minimal deliver_sm parser to extract:
      source_addr, destination_addr, short_message, esm_class

    deliver_sm body layout (similar to submit_sm for first fields):
      service_type (cstring)
      source_addr_ton (1), source_addr_npi (1), source_addr (cstring)
      dest_addr_ton (1), dest_addr_npi (1), destination_addr (cstring)
      esm_class (1), protocol_id (1), priority_flag (1)
      schedule_delivery_time (cstring)
      validity_period (cstring)
      registered_delivery (1)
      replace_if_present_flag (1)
      data_coding (1)
      sm_default_msg_id (1)
      sm_length (1)
      short_message (octets)
      (optional TLVs ignored)
    """
    off = 0
    _, off = read_cstring(body, off)          # service_type

    off += 1  # source_addr_ton
    off += 1  # source_addr_npi
    src, off = read_cstring(body, off)

    off += 1  # dest_addr_ton
    off += 1  # dest_addr_npi
    dst, off = read_cstring(body, off)

    esm_class = body[off] if off < len(body) else 0
    off += 1  # esm_class
    off += 1  # protocol_id
    off += 1  # priority_flag

    _, off = read_cstring(body, off)          # schedule_delivery_time
    _, off = read_cstring(body, off)          # validity_period

    off += 1  # registered_delivery
    off += 1  # replace_if_present_flag
    off += 1  # data_coding
    off += 1  # sm_default_msg_id

    if off >= len(body):
        return src, dst, esm_class, ""

    sm_len = body[off]
    off += 1
    sm = body[off:off + sm_len].decode("utf-8", errors="replace")
    return src, dst, esm_class, sm


def dlr_is_final_for_message(dlr_text: str, msg_id: str) -> bool:
    """
    Heuristic for classic DLR text like:
      id:XYZ ... stat:DELIVRD ...
    We check:
      - id matches msg_id (exact string after 'id:')
      - stat is final (DELIVRD/UNDELIV/REJECTD/EXPIRED)
    """
    if not dlr_text or not msg_id:
        return False

    # Extract id:
    # common forms: "id:abc" or "id: abc"
    tid = None
    parts = dlr_text.split()
    for p in parts:
        if p.startswith("id:"):
            tid = p[3:].strip()
            break
    if tid is None:
        return False

    if tid != msg_id:
        return False

    # Extract stat:
    stat = None
    for p in parts:
        if p.startswith("stat:"):
            stat = p[5:].strip().upper()
            break

    return stat in {"DELIVRD", "UNDELIV", "REJECTD", "EXPIRED"}


def main():
    ap = argparse.ArgumentParser(description="SMPP 3.4 test client (BIND_TRANSCEIVER + submit_sm + wait DLR)")
    ap.add_argument("--host", default="217.182.34.231")
    ap.add_argument("--port", type=int, default=2775)
    ap.add_argument("--system-id", default="origin")
    ap.add_argument("--password", default="origin")
    ap.add_argument("--system-type", default="")
    ap.add_argument("--src", default="1000", help="source_addr")
    ap.add_argument("--dst", default="8801734936561", help="destination_addr")
    ap.add_argument("--text", default="G-241652 is your GOOGLE verification code. Don't share your code with anyone.")
    ap.add_argument("--enquire-interval", type=float, default=10.0, help="Send ENQUIRE_LINK every N seconds while waiting")
    ap.add_argument("--dlr-timeout", type=float, default=120.0, help="How long to wait for final DLR (seconds)")
    ap.add_argument("--no-dlr", action="store_true", help="Do NOT request DLR in submit_sm")
    args = ap.parse_args()

    seq = 1

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(10)

        print(f"Connecting to {args.host}:{args.port} ...")

        st, rseq, _ = bind_transceiver(sock, args.system_id, args.password, args.system_type, seq)
        print(f"BIND_TRANSCEIVER_RESP: status=0x{st:08x}, seq={rseq}")
        if st != ESME_ROK:
            print("Bind failed. Exiting.")
            sys.exit(2)
        seq += 1

        st, rseq, msg_id = submit_sm(
            sock, args.src, args.dst, args.text, seq,
            request_dlr=(not args.no_dlr)
        )
        print(f"SUBMIT_SM_RESP: status=0x{st:08x}, seq={rseq}, message_id={msg_id!r}")
        if st != ESME_ROK:
            print("submit_sm failed. Exiting.")
            sys.exit(3)
        seq += 1

        # Wait for DELIVER_SM (DLR)
        deadline = time.time() + args.dlr_timeout
        next_enquire = time.time() + args.enquire_interval
        got_final = False

        print(f"Waiting for delivery report (timeout={args.dlr_timeout}s) ...")
        while time.time() < deadline:
            # keepalive
            if args.enquire_interval > 0 and time.time() >= next_enquire:
                try:
                    st, rseq = enquire_link(sock, seq)
                    print(f"ENQUIRE_LINK_RESP: status=0x{st:08x}, seq={rseq}")
                    seq += 1
                except socket.timeout:
                    print("ENQUIRE_LINK_RESP timeout (continuing)")
                next_enquire = time.time() + args.enquire_interval

            # receive PDUs (non-block too long)
            try:
                _, cmd_id, status, rseq, body = recv_pdu(sock)
            except socket.timeout:
                continue

            if cmd_id == DELIVER_SM:
                src, dst, esm_class, sm = parse_deliver_sm(body)
                print(f"DELIVER_SM: status=0x{status:08x}, seq={rseq}, src={src!r}, dst={dst!r}, esm_class=0x{esm_class:02x}")
                print(f"  short_message={sm!r}")

                # Must ACK it
                resp = build_pdu(DELIVER_SM_RESP, ESME_ROK, rseq, b"")
                sock.sendall(resp)

                if dlr_is_final_for_message(sm, msg_id):
                    print("Final DLR received for submitted message_id.")
                    got_final = True
                    break

            elif cmd_id == ENQUIRE_LINK:
                # Some servers may ping the client too
                resp = build_pdu(ENQUIRE_LINK_RESP, ESME_ROK, rseq, b"")
                sock.sendall(resp)

            elif cmd_id == UNBIND:
                # server initiated close
                resp = build_pdu(UNBIND_RESP, ESME_ROK, rseq, b"")
                sock.sendall(resp)
                print("Server sent UNBIND; exiting wait loop.")
                break

            else:
                print(f"Received PDU cmd_id=0x{cmd_id:08x} status=0x{status:08x} seq={rseq} (ignored)")

        if not got_final:
            print("Did not receive final DLR before timeout.")

        st, rseq = unbind(sock, seq)
        print(f"UNBIND_RESP: status=0x{st:08x}, seq={rseq}")
        print("Done.")


if __name__ == "__main__":
    main()