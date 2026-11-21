#!/usr/bin/env python3
"""Prepare and verify one private Vaultwarden deployment."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener
import uuid


IMAGE = "vaultwarden/server@sha256:4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f"
LOOPBACK = "http://127.0.0.1:8223"
HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z0-9]+\.ts\.net\Z")
FILES = {"db.sqlite3", "rsa_key.pem"}
EXTRA_FILES = {"config.json", "rsa_key.pub.pem"}
ASSET_DIRS = {"attachments", "sends"}


def command(*args, timeout=30):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f"{Path(args[0]).name} command failed (exit {result.returncode}).")
    return result.stdout


def address(args):
    if not HOST.fullmatch(args.host) or not 1024 <= args.port <= 65535:
        raise ValueError("Use your node's Tailscale FQDN and an HTTPS port between 1024 and 65535.")
    return f"{args.host}:{args.port}"


def plan(args):
    domain = address(args)
    print(f"""# Save as compose.yaml in an empty directory.
services:
  vaultwarden:
    image: {IMAGE}
    restart: unless-stopped
    environment:
      DOMAIN: https://{domain}
      SIGNUPS_ALLOWED: "false"
      INVITATIONS_ALLOWED: "false"
      DISABLE_ICON_DOWNLOAD: "true"
    ports:
      - "127.0.0.1:8223:80"
    volumes:
      - ./data:/data""")


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def check(args):
    domain = address(args)
    config = json.loads(command("tailscale", "serve", "status", "--json"))
    entry = (config.get("Web") or {}).get(domain, {})
    if entry.get("Handlers", {}).get("/", {}).get("Proxy") != LOOPBACK:
        raise ValueError("The configured Tailscale route does not point to the expected loopback service.")
    if (config.get("AllowFunnel") or {}).get(domain):
        raise ValueError("Funnel is enabled for this endpoint. Switch it to private Tailscale Serve.")
    opener = build_opener(ProxyHandler({}), RejectRedirects())
    with opener.open(f"https://{domain}/alive", timeout=8) as response:
        if response.geturl() != f"https://{domain}/alive" or response.status != 200:
            raise ValueError("Vault health endpoint redirected or returned an unexpected status.")
        json.loads(response.read(4096))
    print("Tailscale Serve route and HTTPS health passed. Check device access separately.")


def snapshot_inputs(data):
    paths = [data / name for name in FILES | EXTRA_FILES]
    for name in sorted(ASSET_DIRS):
        directory = data / name
        if directory.is_symlink():
            raise ValueError("Vault asset directory is a symlink.")
        if directory.exists() and not directory.is_dir():
            raise ValueError("Vault asset path is not a directory.")
        paths.extend(directory.rglob("*"))
    result = {}
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError("Vault backup input includes a symlink.")
        if not path.exists() or path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("Vault backup input includes a special file.")
        stat = path.stat()
        result[path.relative_to(data).as_posix()] = (
            stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if not FILES <= result.keys():
        raise ValueError("Vault data directory must contain db.sqlite3 and rsa_key.pem.")
    return result


def backup(args):
    data = args.data.resolve(strict=True)
    output = args.output.absolute()
    if output.resolve().is_relative_to(data):
        raise ValueError("Store the archive outside the live vault data directory.")
    if output.exists() or output.is_symlink():
        raise ValueError("Backup already exists. Choose a fresh filename.")
    before = snapshot_inputs(data)
    wal = data / "db.sqlite3-wal"

    def wal_signature():
        if wal.is_symlink():
            raise ValueError("SQLite WAL is a symlink.")
        try:
            stat = wal.stat()
        except FileNotFoundError:
            return None
        return stat.st_ino, stat.st_size, stat.st_mtime_ns

    before_wal = wal_signature()
    with (tempfile.TemporaryDirectory(prefix="vault-plaintext-") as scratch,
          tempfile.TemporaryDirectory(prefix=".vault-ciphertext-", dir=output.parent) as encrypted):
        snapshot = Path(scratch) / "db.sqlite3"
        with sqlite3.connect((data / "db.sqlite3").as_uri() + "?mode=ro", uri=True) as live:
            with sqlite3.connect(snapshot) as copy:
                live.backup(copy)
        counts = database_counts(snapshot)
        staged = Path(encrypted) / "backup.age"
        with staged.open("xb") as ciphertext:
            with subprocess.Popen(["age", "--encrypt", "-r", args.recipient], stdin=subprocess.PIPE,
                                  stdout=ciphertext, stderr=subprocess.DEVNULL) as encrypt:
                def files_only(member):
                    if not member.isfile():
                        raise ValueError("Backup input changed to a non-regular file.")
                    return member

                with tarfile.open(fileobj=encrypt.stdin, mode="w|gz") as archive:
                    for name in before:
                        source = snapshot if name == "db.sqlite3" else data / name
                        archive.add(source, arcname=name, recursive=False, filter=files_only)
                encrypt.stdin.close()
                if encrypt.wait() != 0:
                    raise ValueError("age encryption failed. Check the recipient public key.")
            ciphertext.flush()
            os.fsync(ciphertext.fileno())
        if snapshot_inputs(data) != before or wal_signature() != before_wal:
            raise ValueError("Vault files changed during backup. Stop Vaultwarden and retry.")
        with staged.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        os.link(staged, output)
    print(f"Encrypted backup created with {counts['accounts']} account(s) and "
          f"{counts['encrypted_items']} encrypted item(s).")
    print(f"SHA-256: {digest}")


def extract_snapshot(source, identity, destination):
    found = set()
    assets = set()
    prefix = None
    with subprocess.Popen(["age", "--decrypt", "-i", str(identity)], stdin=source,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as decrypt:
        try:
            with tarfile.open(fileobj=decrypt.stdout, mode="r|gz") as members:
                for entry in members:
                    parts = entry.name.removeprefix("./").split("/")
                    is_asset = parts[0] in ASSET_DIRS and len(parts) > 1 and not entry.isdir()
                    if parts[-1] not in FILES and not is_asset:
                        continue
                    if (not entry.isfile() or (not is_asset and entry.size == 0) or entry.size > 1024**3
                            or any(part in ("", "..", ".") for part in parts)):
                        raise ValueError("Invalid vault backup member.")
                    if is_asset:
                        asset = "/".join(parts)
                        if asset in assets:
                            raise ValueError("Duplicate asset in vault backup.")
                        target = destination.joinpath(*parts)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with members.extractfile(entry) as content, target.open("xb") as out:
                            shutil.copyfileobj(content, out)
                        assets.add(asset)
                        continue
                    location = tuple(parts[:-1])
                    if parts[-1] in found or (prefix is not None and prefix != location):
                        raise ValueError("Ambiguous vault backup. Supply an archive with one vault.")
                    prefix = location
                    with members.extractfile(entry) as source, (destination / parts[-1]).open("xb") as out:
                        shutil.copyfileobj(source, out)
                    found.add(parts[-1])
            for _ in iter(lambda: decrypt.stdout.read(65536), b""):
                pass
            if decrypt.wait() != 0 or found != FILES:
                raise ValueError("Could not authenticate archive or locate the database and server key.")
            return len(assets)
        except (tarfile.TarError, EOFError) as error:
            raise ValueError("Could not decrypt a gzip tar backup. Check the recovery key and archive.") from error
        finally:
            if decrypt.poll() is None:
                decrypt.terminate()
                decrypt.wait()


def database_counts(database):
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("SQLite integrity check failed.")
        return {"accounts": db.execute("SELECT count(*) FROM users WHERE length(password_hash)>0").fetchone()[0],
                "encrypted_items": db.execute("SELECT count(*) FROM ciphers").fetchone()[0]}


def boot_restore(data, docker):
    name = f"vault-restore-{uuid.uuid4().hex[:12]}"
    command(*docker, "image", "inspect", IMAGE)
    try:
        command(*docker, "run", "--pull", "never", "--detach", "--name", name, "--network", "none",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "-e", "SIGNUPS_ALLOWED=false", "-e", "INVITATIONS_ALLOWED=false",
                "-e", "DISABLE_ICON_DOWNLOAD=true", "-v", f"{data}:/data", IMAGE)
        for _ in range(25):
            try:
                command(*docker, "exec", name, "/healthcheck.sh", timeout=5)
                return
            except ValueError:
                time.sleep(1)
        raise ValueError("The restored vault did not become healthy.")
    finally:
        known = subprocess.run([*docker, "inspect", name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10)
        if known.returncode == 0:
            command(*docker, "container", "rm", "--force", name)


def restore(args):
    with args.archive.open("rb") as stream, tempfile.TemporaryDirectory(prefix="vault-restore-") as trial:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != args.sha256.lower():
            raise ValueError("SHA-256 differs from the expected backup checksum.")
        stream.seek(0)
        data = Path(trial)
        asset_count = extract_snapshot(stream, args.identity, data)
        stream.seek(0)
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError("The backup changed during verification.")
        counts = database_counts(data / "db.sqlite3")
        docker = ("sudo", "-n", "docker") if args.sudo_docker else ("docker",)
        boot_restore(data, docker)
    receipt = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "archive_sha256": digest, "isolated_startup": "passed",
               "asset_files_copied": asset_count, **counts}
    with args.receipt.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(f"Restored vault booted with {counts['accounts']} account(s) and "
          f"{counts['encrypted_items']} encrypted item(s). Receipt saved.")


def status(args):
    with args.receipt.open(encoding="utf-8") as stream:
        receipt = json.load(stream)
    if (not isinstance(receipt, dict) or receipt.get("isolated_startup") != "passed"
            or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("archive_sha256", "")))):
        raise ValueError("No valid isolated restore receipt.")
    try:
        checked = datetime.fromisoformat(receipt.get("checked_at", ""))
        age = datetime.now(timezone.utc) - checked
    except (TypeError, ValueError) as error:
        raise ValueError("Restore receipt timestamp is invalid.") from error
    if age.total_seconds() < 0:
        raise ValueError("Restore receipt is dated in the future.")
    if not 1 <= args.max_age_days <= 365:
        raise ValueError("Maximum receipt age must be 1–365 days.")
    if age.total_seconds() > args.max_age_days * 86400:
        raise ValueError(f"Last isolated restore was {age.days} days ago. Run a fresh restore drill.")
    print(f"Isolated restore passed on {checked.date().isoformat()} ({age.days} days ago).")
    print("This receipt covers server startup only. Confirm client access and item decryption separately.")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for label, handler in (("plan", plan), ("check", check)):
        sub = actions.add_parser(label)
        sub.add_argument("--host", required=True)
        sub.add_argument("--port", type=int, default=8447)
        sub.set_defaults(run=handler)
    sub = actions.add_parser("backup", help="Create an encrypted backup from a Vaultwarden data directory.")
    sub.add_argument("--data", type=Path, required=True)
    sub.add_argument("--recipient", required=True, help="age public key; keep its private key off-host.")
    sub.add_argument("--output", type=Path, required=True)
    sub.set_defaults(run=backup)
    sub = actions.add_parser("restore-check")
    sub.add_argument("archive", type=Path)
    sub.add_argument("--sha256", required=True)
    sub.add_argument("--identity", type=Path, required=True)
    sub.add_argument("--receipt", type=Path, required=True)
    sub.add_argument("--sudo-docker", action="store_true")
    sub.set_defaults(run=restore)
    sub = actions.add_parser("status", help="Check the age of a recorded isolated restore.")
    sub.add_argument("--receipt", type=Path, required=True)
    sub.add_argument("--max-age-days", type=int, default=30)
    sub.set_defaults(run=status)
    args = parser.parse_args()
    try:
        args.run(args)
    except (OSError, ValueError, URLError, sqlite3.Error, tarfile.TarError, subprocess.TimeoutExpired) as error:
        print(f"Check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
