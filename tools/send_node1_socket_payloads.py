#!/usr/bin/env python3
"""
Send low-volume test traffic to node1's streetlight socket honeypot.

This is intended for validating that node1 logs custom/TCP payloads and that
the ElastAlert "TCP Payload Sent" rule creates alerts.
"""

from __future__ import annotations

import argparse
import socket
import time


DEFAULT_PAYLOADS = [
    # Known streetlight gateway commands from node1's package.
    bytes.fromhex("020B52123456789A013240"),
    bytes.fromhex("020C36408110143701023295"),
    bytes.fromhex("020A50123456789A010B"),
    # Clearly identifiable probe strings for log searching.
    b"malicious-test node1 streetlight probe\n",
    b"../../../../etc/passwd;cat /etc/shadow\n",
]


def send_payload(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        try:
            return sock.recv(4096)
        except socket.timeout:
            return b""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send test socket payloads to node1 streetlight honeypot."
    )
    parser.add_argument("--host", default="35.212.184.5", help="node1 public IP or DNS")
    parser.add_argument("--port", type=int, default=5566, help="node1 proxy listen port")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between payloads")
    parser.add_argument(
        "--payload-hex",
        action="append",
        default=[],
        help="extra payload as hex; can be passed multiple times",
    )
    parser.add_argument(
        "--payload-text",
        action="append",
        default=[],
        help="extra payload as text; can be passed multiple times",
    )
    parser.add_argument(
        "--overflow-test-size",
        type=int,
        default=0,
        help="append a benign oversized A-pattern payload of this many bytes",
    )
    args = parser.parse_args()

    payloads = list(DEFAULT_PAYLOADS)
    for value in args.payload_hex:
        payloads.append(bytes.fromhex(value.strip().replace(" ", "")))
    for value in args.payload_text:
        payloads.append(value.encode("utf-8"))
    if args.overflow_test_size:
        if args.overflow_test_size < 1:
            parser.error("--overflow-test-size must be positive")
        payloads.append(b"A" * args.overflow_test_size)

    print(f"Target: {args.host}:{args.port}")
    for index, payload in enumerate(payloads, start=1):
        preview = payload.hex()
        if len(preview) > 80:
            preview = preview[:80] + "..."
        print(f"[{index}/{len(payloads)}] sending {len(payload)} bytes: {preview}")
        try:
            response = send_payload(args.host, args.port, payload, args.timeout)
        except OSError as exc:
            print(f"  error: {exc}")
        else:
            if response:
                print(f"  response {len(response)} bytes: {response.hex()[:160]}")
            else:
                print("  no response")
        if index != len(payloads):
            time.sleep(args.delay)

    print("Done. Check Live Attack Feed and Alerts for node_1 / protocol custom.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
