#!/usr/bin/env python3
"""Realign entity ids with their friendly names.

Home Assistant derives an entity id from the device name at first discovery and never
revises it when the device is renamed upstream. Over time the ids stop describing what
they control: in this install `light.kitchen` is the Bathroom and `light.floor_lamp` is
a ceiling fan bulb. This tool reads the live registry, proposes ids that match the
current friendly names, and applies them once a human has reviewed the list.

Three phases, with a review gate in the middle:

    python3 tools/ha_entity_rename.py plan             # read-only, writes the proposal
    $EDITOR entity-renames.json                        # flip "apply" where wrong
    python3 tools/ha_entity_rename.py apply --yes      # performs the renames
    python3 tools/ha_entity_rename.py refs             # find broken references

Run it from the Studio Code Server add-on terminal, where SUPERVISOR_TOKEN is already
set. Outside the add-on, pass --url and --token for a long-lived access token.

Standard library only: the add-on container is not Home Assistant's venv, so neither
`websockets` nor `slugify` can be assumed present. Renaming an entity id is only
possible over the WebSocket API, so a minimal RFC 6455 client lives in here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent

PLAN_FILE = ROOT / "entity-renames.json"
APPLIED_FILE = ROOT / "entity-renames.applied.json"
INVENTORY_FILE = ROOT / "entity-inventory.txt"
REGISTRY_FILE = ROOT / ".storage" / "core.entity_registry"

SUPERVISOR_WS = "ws://supervisor/core/websocket"

# Files worth searching for stale references. .storage is handled separately and is
# never written to.
REF_GLOBS = ("*.yaml", "*.json", "dashboards/*.yaml", "themes/*.yaml")

# Reported but never rewritten: current-dashboard.json is an export of the UI-storage
# dashboard, so editing it here would make it misdescribe what is actually deployed.
# Fix those in the browser editor instead.
REF_READONLY = ("current-dashboard.json",)


class HaError(RuntimeError):
    """A command came back with success: false."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class AuthError(RuntimeError):
    """Reached Home Assistant, but it rejected the token."""


# ---------------------------------------------------------------------------
# Minimal RFC 6455 client. Enough of the protocol to talk to Home Assistant:
# text frames, continuation, ping/pong, close. No extensions, no compression.
# ---------------------------------------------------------------------------
class WebSocket:
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        parts = urlparse(url)
        secure = parts.scheme == "wss"
        host = parts.hostname or ""
        port = parts.port or (443 if secure else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        self._buf = b""
        self.sock = socket.create_connection((host, port), timeout=timeout)
        if secure:
            self.sock = ssl.create_default_context().wrap_socket(
                self.sock, server_hostname=host
            )
        self._handshake(host, port, path, secure)

    def _handshake(self, host: str, port: int, path: str, secure: bool) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        default_port = 443 if secure else 80
        host_header = host if port == default_port else f"{host}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode())

        blob = b""
        while b"\r\n\r\n" not in blob:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("server closed during handshake")
            blob += chunk
        header_blob, _, self._buf = blob.partition(b"\r\n\r\n")

        lines = header_blob.decode("latin-1").split("\r\n")
        if "101" not in lines[0]:
            raise ConnectionError(f"upgrade refused: {lines[0]}")

        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()

        expected = base64.b64encode(
            hashlib.sha1((key + self.GUID).encode()).digest()
        ).decode()
        if headers.get("sec-websocket-accept") != expected:
            raise ConnectionError("bad Sec-WebSocket-Accept; not a websocket peer")

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed mid-frame")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _recv_frame(self) -> tuple[bool, int, bytes]:
        b0, b1 = self._read(2)
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read(8))[0]
        mask = self._read(4) if b1 & 0x80 else None
        payload = self._read(length) if length else b""
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])
        n = len(payload)
        # Client frames must always be masked (RFC 6455 §5.3).
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", n)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def recv_text(self) -> str:
        frags: list[bytes] = []
        while True:
            fin, opcode, payload = self._recv_frame()
            if opcode == 0x8:
                raise ConnectionError("server sent close")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            frags = [payload] if opcode in (0x1, 0x2) else frags + [payload]
            if fin:
                return b"".join(frags).decode("utf-8")

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        finally:
            self.sock.close()


class HaClient:
    """The Home Assistant websocket protocol on top of the frame layer."""

    def __init__(self, url: str, token: str) -> None:
        self.ws = WebSocket(url)
        self._id = 0

        hello = json.loads(self.ws.recv_text())
        if hello.get("type") != "auth_required":
            raise ConnectionError(f"unexpected greeting: {hello.get('type')}")
        self.ws.send_text(json.dumps({"type": "auth", "access_token": token}))
        reply = json.loads(self.ws.recv_text())
        if reply.get("type") != "auth_ok":
            raise AuthError(reply.get("message") or reply.get("type", "rejected"))

    def command(self, type_: str, **kwargs: object) -> object:
        self._id += 1
        mid = self._id
        self.ws.send_text(json.dumps({"id": mid, "type": type_, **kwargs}))
        while True:
            msg = json.loads(self.ws.recv_text())
            if msg.get("id") != mid or msg.get("type") != "result":
                continue
            if not msg.get("success"):
                err = msg.get("error") or {}
                raise HaError(err.get("code", "unknown"), err.get("message", ""))
            return msg.get("result")

    def close(self) -> None:
        self.ws.close()


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

# Home Assistant slugs with python-slugify, which deletes apostrophes rather than
# turning them into separators: "Star's Lamp" becomes stars_lamp, not star_s_lamp.
_APOSTROPHES = "'’ʼʻ`´"


def slugify(text: str | None) -> str:
    """Reproduce homeassistant.util.slugify without the dependency."""
    if not text:
        return ""
    text = "".join(ch for ch in text if ch not in _APOSTROPHES)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    return slug or "unknown"


def display_name(entry: dict, states: dict) -> str | None:
    """What the user actually sees, which is what the id should match.

    The state's friendly_name wins: for entities using has_entity_name it is the
    composed "Device Name Entity Name", whereas the registry only holds the parts.
    """
    state = states.get(entry["entity_id"])
    if state:
        friendly = (state.get("attributes") or {}).get("friendly_name")
        if friendly:
            return friendly
    return entry.get("name") or entry.get("original_name")


def connect(args: argparse.Namespace) -> HaClient:
    token = args.token or os.environ.get("SUPERVISOR_TOKEN") or os.environ.get(
        "HA_TOKEN"
    )
    if not token:
        sys.exit(
            "No token. Run this in the Studio Code Server add-on terminal where\n"
            "SUPERVISOR_TOKEN is set, or pass --token with a long-lived access token."
        )
    url = args.url or (
        SUPERVISOR_WS if os.environ.get("SUPERVISOR_TOKEN") else None
    )
    if not url:
        sys.exit("No --url given and SUPERVISOR_TOKEN is not set.")
    try:
        return HaClient(url, token)
    except AuthError as exc:
        sys.exit(
            f"Home Assistant rejected the token ({exc}).\n"
            "Inside the add-on, SUPERVISOR_TOKEN should be used automatically; "
            "outside it, --token needs a long-lived access token."
        )
    except (OSError, ConnectionError) as exc:
        sys.exit(f"Could not reach {url}: {exc}")


def fetch(client: HaClient) -> tuple[list[dict], dict]:
    entries = client.command("config/entity_registry/list")
    states = {s["entity_id"]: s for s in client.command("get_states")}
    return list(entries), states


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------
def cmd_plan(args: argparse.Namespace) -> int:
    client = connect(args)
    try:
        entries, states = fetch(client)
    finally:
        client.close()

    taken = {e["entity_id"] for e in entries}
    platforms = {p.lower() for p in args.platform}
    domains = {d.lower() for d in args.domain} if args.domain else None

    proposals: list[dict] = []
    for entry in sorted(entries, key=lambda e: e["entity_id"]):
        entity_id = entry["entity_id"]
        domain = entity_id.split(".", 1)[0]

        if "all" not in platforms and (entry.get("platform") or "").lower() not in platforms:
            continue
        if domains and domain not in domains:
            continue

        name = display_name(entry, states)
        if not name:
            continue
        proposed = f"{domain}.{slugify(name)}"
        if proposed == entity_id:
            continue

        proposals.append(
            {
                "entity_id": entity_id,
                "friendly_name": name,
                "proposed_entity_id": proposed,
                "apply": True,
                "note": "",
            }
        )

    # Collisions: against every id in the registry, and against each other. Never
    # resolved automatically -- a wrong guess here silently points a dashboard at
    # someone else's light.
    counts: dict[str, int] = {}
    for p in proposals:
        counts[p["proposed_entity_id"]] = counts.get(p["proposed_entity_id"], 0) + 1

    blocked = 0
    for p in proposals:
        target = p["proposed_entity_id"]
        if target in taken:
            p["apply"] = False
            p["note"] = f"COLLISION: {target} already exists"
            blocked += 1
        elif counts[target] > 1:
            p["apply"] = False
            p["note"] = f"COLLISION: {counts[target]} entities want {target}"
            blocked += 1

    PLAN_FILE.write_text(
        json.dumps(
            {
                "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "platform": sorted(platforms),
                "domain": sorted(domains) if domains else "all",
                "renames": proposals,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    ready = sum(1 for p in proposals if p["apply"])
    print(f"{len(entries)} entities in the registry")
    print(f"{len(proposals)} mismatched, {ready} ready to apply, {blocked} blocked\n")
    for p in proposals:
        flag = " " if p["apply"] else "!"
        print(f" {flag} {p['entity_id']:42} -> {p['proposed_entity_id']:42} {p['note']}")
    print(f"\nWrote {PLAN_FILE.relative_to(ROOT)}")
    print('Review it, set "apply": false on anything unwanted, then run: apply --yes')
    if blocked:
        print(f"{blocked} blocked on collisions -- resolve by hand or leave disabled.")
    return 0


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------
def cmd_apply(args: argparse.Namespace) -> int:
    path = Path(args.input) if args.input else (
        APPLIED_FILE if args.revert else PLAN_FILE
    )
    if not path.exists():
        sys.exit(f"{path} not found. Run `plan` first.")

    data = json.loads(path.read_text(encoding="utf-8"))
    renames = data.get("renames", [])

    if args.revert:
        pending = [
            {
                "entity_id": r["proposed_entity_id"],
                "proposed_entity_id": r["entity_id"],
                "friendly_name": r.get("friendly_name", ""),
            }
            for r in renames
            if r.get("applied")
        ]
    else:
        pending = [r for r in renames if r.get("apply")]
        bad = [r for r in pending if r.get("note", "").startswith("COLLISION")]
        if bad:
            for r in bad:
                print(f"  {r['entity_id']}: {r['note']}", file=sys.stderr)
            plural = "entry still carries" if len(bad) == 1 else "entries still carry"
            sys.exit(
                f"\n{len(bad)} {plural} a collision while marked apply:true. "
                "Fix the target id or set apply:false."
            )

    if not pending:
        print("Nothing to do.")
        return 0

    verb = "Reverting" if args.revert else "Renaming"
    print(f"{verb} {len(pending)} entities:\n")
    for r in pending:
        print(f"  {r['entity_id']:42} -> {r['proposed_entity_id']}")

    if not args.yes:
        if input("\nProceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    client = connect(args)
    try:
        live = {e["entity_id"] for e in client.command("config/entity_registry/list")}

        done, skipped, failed = [], [], []
        for r in pending:
            old, new = r["entity_id"], r["proposed_entity_id"]
            # Idempotent: a partial run can be re-run without erroring.
            if old not in live and new in live:
                skipped.append(r)
                print(f"  skip   {old} (already {new})")
                continue
            try:
                client.command(
                    "config/entity_registry/update",
                    entity_id=old,
                    new_entity_id=new,
                )
            except HaError as exc:
                failed.append((r, str(exc)))
                print(f"  FAIL   {old} -> {new}: {exc}", file=sys.stderr)
                continue
            r["applied"] = True
            done.append(r)
            print(f"  ok     {old} -> {new}")
    finally:
        client.close()

    if not args.revert and done:
        APPLIED_FILE.write_text(
            json.dumps(
                {
                    "applied": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "renames": done,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nLogged to {APPLIED_FILE.relative_to(ROOT)} (revert with: apply --revert)")

    print(f"\n{len(done)} renamed, {len(skipped)} already done, {len(failed)} failed")

    if done:
        regenerate_inventory()
        if not args.revert:
            print("Now run `refs` to find references that need updating.")
    return 1 if failed else 0


def regenerate_inventory() -> None:
    """Refresh entity-inventory.txt from the registry, per README.md."""
    if not REGISTRY_FILE.exists():
        print(f"(skipped inventory: {REGISTRY_FILE} not found -- not on the HA box?)")
        return
    data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    ids = sorted(e["entity_id"] for e in data["data"]["entities"])
    INVENTORY_FILE.write_text("\n".join(ids) + "\n", encoding="utf-8")
    print(f"Regenerated {INVENTORY_FILE.relative_to(ROOT)} ({len(ids)} entities)")


# ---------------------------------------------------------------------------
# refs
# ---------------------------------------------------------------------------
def cmd_refs(args: argparse.Namespace) -> int:
    path = Path(args.input) if args.input else APPLIED_FILE
    if not path.exists():
        sys.exit(f"{path} not found. Run `apply` first, or pass --input.")

    data = json.loads(path.read_text(encoding="utf-8"))
    mapping = {
        r["entity_id"]: r["proposed_entity_id"]
        for r in data.get("renames", [])
        if r.get("applied") or r.get("apply")
    }
    if not mapping:
        print("No renames in that file.")
        return 0

    pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in mapping) + r")\b")

    targets: list[Path] = []
    for glob in REF_GLOBS:
        targets.extend(sorted(ROOT.glob(glob)))
    # Never scan our own bookkeeping: rewriting the old ids inside the applied log
    # would destroy the reverse mapping that --revert depends on.
    ours = {PLAN_FILE, APPLIED_FILE, path.resolve()}
    targets = [
        p for p in dict.fromkeys(targets) if p.is_file() and p.resolve() not in ours
    ]

    total, changed_files = 0, 0
    for file in targets:
        try:
            text = file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        hits = pattern.findall(text)
        if not hits:
            continue
        rel = file.relative_to(ROOT)
        readonly = file.name in REF_READONLY
        total += len(hits)
        for lineno, line in enumerate(text.splitlines(), 1):
            for old in set(pattern.findall(line)):
                mark = " [read-only]" if readonly else ""
                print(f"  {rel}:{lineno}  {old} -> {mapping[old]}{mark}")
        if args.write and not readonly:
            file.write_text(pattern.sub(lambda m: mapping[m.group(1)], text), "utf-8")
            changed_files += 1

    # .storage holds the UI dashboards. Report only: it is gitignored, and rewriting
    # live storage JSON underneath a running Home Assistant is not worth the risk.
    storage = ROOT / ".storage"
    storage_hits = 0
    if storage.is_dir():
        for file in sorted(storage.glob("lovelace*")):
            try:
                text = file.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            found = set(pattern.findall(text))
            for old in sorted(found):
                storage_hits += 1
                print(f"  [.storage] {file.name}  {old} -> {mapping[old]}")

    print(f"\n{total} reference(s) in tracked files across {len(targets)} scanned")
    if args.write:
        print(f"Rewrote {changed_files} file(s). Review with: git diff")
    elif total:
        print("Re-run with --write to rewrite them.")
    if storage_hits:
        print(
            f"{storage_hits} reference(s) in .storage -- fix these in the browser "
            "dashboard editor, they are not rewritten here."
        )
    return 0


# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `plan` first; it is read-only.",
    )
    parser.add_argument("--url", help=f"websocket url (default: {SUPERVISOR_WS})")
    parser.add_argument("--token", help="access token (default: $SUPERVISOR_TOKEN)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan", help="propose renames; writes entity-renames.json")
    p.add_argument(
        "--platform",
        action="append",
        default=None,
        help="integration to include, repeatable, or 'all' (default: hue)",
    )
    p.add_argument(
        "--domain",
        action="append",
        default=None,
        help="entity domain to include, repeatable (default: all)",
    )
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("apply", help="perform the renames in entity-renames.json")
    p.add_argument("-i", "--input", help="input file")
    p.add_argument("-y", "--yes", action="store_true", help="skip the confirmation")
    p.add_argument("--revert", action="store_true", help="undo an applied batch")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("refs", help="find config references to renamed entities")
    p.add_argument("-i", "--input", help="input file (default: applied log)")
    p.add_argument("--write", action="store_true", help="rewrite tracked files")
    p.set_defaults(func=cmd_refs)

    args = parser.parse_args()
    if args.cmd == "plan" and not args.platform:
        args.platform = ["hue"]
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
