#!/usr/bin/env python3
"""Test disposable local database containers; never uses application databases."""
import os
import pathlib
import subprocess
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
PASSWORD = "foctet-disposable-test"
SUFFIX = uuid.uuid4().hex[:10]


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


cases = [
    ("mysql", "mysql:8.4", 3306, ["-e", f"MYSQL_ROOT_PASSWORD={PASSWORD}", "-e", "MYSQL_DATABASE=foctet_test"],
     ["mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", f"-p{PASSWORD}"]),
    ("mariadb", "mariadb:12.3.3", 3306, ["-e", f"MARIADB_ROOT_PASSWORD={PASSWORD}", "-e", "MARIADB_DATABASE=foctet_test"],
     ["healthcheck.sh", "--connect", "--innodb_initialized"]),
    ("postgres", "postgres:17", 5432, ["-e", f"POSTGRES_PASSWORD={PASSWORD}", "-e", "POSTGRES_DB=foctet_test"],
     ["pg_isready", "-U", "postgres", "-d", "foctet_test"]),
    ("turso", "ghcr.io/tursodatabase/libsql-server@sha256:6dd3eb276d9d3604e4a48ac4a999a2e267814732d57d7e94c04ba71482333a67", 8080,
     ["--platform", "linux/amd64", "-e", "SQLD_NODE=primary"], None),
]
for kind, image, port, options, readiness in cases:
    name = f"foctet-local-{kind}-{SUFFIX}"
    created = False
    try:
        # Ensure schema creation does not depend on a transactional server default.
        command = ["--default-storage-engine=MyISAM"] if kind in ("mysql", "mariadb") else []
        run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1::{port}", *options, image, *command])
        created = True
        address = run(["docker", "port", name, str(port)], capture_output=True).stdout.strip()
        hostport = address.rsplit(":", 1)[1]
        if readiness:
            for _ in range(120):
                ready = subprocess.run(["docker", "exec", name, *readiness], capture_output=True).returncode == 0
                if ready:
                    break
                time.sleep(1)
            else:
                raise RuntimeError(f"{kind} did not become ready")
            # MySQL initialization can briefly expose an intermediate daemon.
            time.sleep(2)
        else:
            import urllib.request
            for _ in range(120):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{hostport}/health", timeout=1):
                        break
                except Exception:
                    time.sleep(1)
            else:
                raise RuntimeError("libSQL did not become ready")
        env = os.environ.copy()
        if kind == "turso":
            env["FOCTET_TEST_TURSO_URL"] = f"http://127.0.0.1:{hostport}"
            test = "turso_remote_conformance"
        else:
            user = "postgres" if kind == "postgres" else "root"
            scheme = "postgres" if kind == "postgres" else "mysql"
            tls = "?ssl-mode=required" if kind == "mysql" else ""
            env["FOCTET_TEST_DATABASE_URL"] = f"{scheme}://{user}:{PASSWORD}@127.0.0.1:{hostport}/foctet_test{tls}"
            test = "server_database_conformance"
        run(["cargo", "test", "-p", "foctet-storage", "--all-features", "--locked", "--test", "databases", test, "--", "--ignored"], env=env)
    finally:
        if created:
            run(["docker", "rm", "-f", name])
