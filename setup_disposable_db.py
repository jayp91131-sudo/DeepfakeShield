#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Disposable Test Database Setup Script
Milestone: V10.1.3 — Migration and Security Repair
Target: PostgreSQL 18.6

Connects using explicitly configured environment credentials, drops and recreates
a clearly named disposable test database (must contain 'test' or 'disposable'),
applies V10_1_3__security_repair.sql, and configures runtime role passwords.

Requires --confirm-drop (or CONFIRM_DISPOSABLE_DB_RESET=true) to execute.
"""

import argparse
import os
import re
import sys
from typing import Dict

import psycopg
from psycopg import sql

_FORBIDDEN_DATABASES = frozenset({"postgres", "template0", "template1", "deepfakeshield_db"})
_DB_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{1,62}$")


def _is_missing_or_placeholder(val: str | None) -> bool:
    if not val:
        return True
    cleaned = val.strip()
    if not cleaned:
        return True
    return (cleaned.startswith("<") and cleaned.endswith(">")) or cleaned.upper().startswith("REPLACE_WITH_")


def _require_env_secret(var_name: str) -> str:
    val = os.environ.get(var_name)
    if _is_missing_or_placeholder(val):
        raise RuntimeError(
            f"CRITICAL SECURITY ERROR: Explicit environment credential '{var_name}' is required "
            "for disposable database setup (insecure default passwords are not permitted)."
        )
    return val.strip()


def validate_disposable_db_name(db_name: str | None) -> str:
    if _is_missing_or_placeholder(db_name):
        raise RuntimeError(
            "CRITICAL SECURITY ERROR: Explicit disposable database name is required via "
            "DISPOSABLE_PGDATABASE (or PGDATABASE). Defaulting to 'deepfakeshield_db' is forbidden."
        )
    cleaned = db_name.strip()
    if cleaned.lower() in _FORBIDDEN_DATABASES:
        raise RuntimeError(
            f"CRITICAL SECURITY ERROR: Refusing to drop/recreate protected database '{cleaned}'. "
            "Specify a dedicated disposable database name containing 'test' or 'disposable'."
        )
    if "test" not in cleaned.lower() and "disposable" not in cleaned.lower():
        raise RuntimeError(
            f"CRITICAL SECURITY ERROR: Database '{cleaned}' does not look like a disposable test database "
            "(name must contain 'test' or 'disposable')."
        )
    if not _DB_NAME_RE.match(cleaned):
        raise RuntimeError(
            f"CRITICAL SECURITY ERROR: Invalid PostgreSQL database identifier '{cleaned}'."
        )
    return cleaned


def get_env_config(confirm_drop: bool = False) -> Dict[str, object]:
    confirmed = confirm_drop or (
        os.environ.get("CONFIRM_DISPOSABLE_DB_RESET", "").strip().lower() == "true"
    )
    if not confirmed:
        raise RuntimeError(
            "Refusing destructive database reset without explicit confirmation: "
            "pass --confirm-drop or set CONFIRM_DISPOSABLE_DB_RESET=true."
        )

    raw_db = os.environ.get("DISPOSABLE_PGDATABASE") or os.environ.get("PGDATABASE")
    db_name = validate_disposable_db_name(raw_db)

    return {
        "host": os.environ.get("PGHOST", "127.0.0.1").strip() or "127.0.0.1",
        "port": int(os.environ.get("PGPORT", "5433")),
        "admin_user": _require_env_secret("PGUSER") if "PGUSER" in os.environ else "postgres",
        "admin_password": _require_env_secret("PGPASSWORD"),
        "database": db_name,
        "app_password": _require_env_secret("APP_PASSWORD"),
        "verifier_password": _require_env_secret("VERIFIER_PASSWORD"),
        "worker_password": _require_env_secret("WORKER_PASSWORD"),
        "auditor_password": _require_env_secret("AUDITOR_PASSWORD"),
    }


def run_setup(confirm_drop: bool = False):
    cfg = get_env_config(confirm_drop=confirm_drop)
    db_name = str(cfg["database"])
    print(f"[*] Initializing disposable PostgreSQL 18 database '{db_name}' on {cfg['host']}:{cfg['port']}...")

    # Step 1: Connect to maintenance db (postgres) as superuser to drop & recreate target disposable db
    try:
        with psycopg.connect(
            host=str(cfg["host"]),
            port=int(cfg["port"]),
            dbname="postgres",
            user=str(cfg["admin_user"]),
            password=str(cfg["admin_password"]),
            autocommit=True,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE);").format(sql.Identifier(db_name))
                )
                cur.execute(
                    sql.SQL("CREATE DATABASE {};").format(sql.Identifier(db_name))
                )
                print(f"[+] Successfully recreated disposable database '{db_name}'.")
    except Exception as e:
        print(f"[-] Failed to recreate database: {e}")
        sys.exit(1)

    # Step 2: Apply V10.1.3 Security Repair Migration
    script_dir = os.path.dirname(os.path.abspath(__file__))
    migration_file = os.path.join(script_dir, "migrations", "V10_1_3__security_repair.sql")
    if not os.path.isfile(migration_file):
        print(f"[-] Migration file not found: {migration_file}")
        sys.exit(1)

    with open(migration_file, "r", encoding="utf-8") as f:
        migration_sql = f.read()

    try:
        with psycopg.connect(
            host=str(cfg["host"]),
            port=int(cfg["port"]),
            dbname=db_name,
            user=str(cfg["admin_user"]),
            password=str(cfg["admin_password"]),
            autocommit=True,
        ) as conn:
            with conn.cursor() as cur:
                print("[*] Applying migration: V10_1_3__security_repair.sql...")
                cur.execute(migration_sql)
                print("[+] Successfully applied V10_1_3__security_repair.sql.")

                # Step 3: Configure credentials for runtime test roles safely
                role_passwords = {
                    "deepfakeshield_app": str(cfg["app_password"]),
                    "deepfakeshield_verifier": str(cfg["verifier_password"]),
                    "deepfakeshield_payout_worker": str(cfg["worker_password"]),
                    "deepfakeshield_auditor": str(cfg["auditor_password"]),
                }
                for role_name, role_pw in role_passwords.items():
                    cur.execute(
                        sql.SQL("ALTER ROLE {} WITH PASSWORD {};").format(
                            sql.Identifier(role_name),
                            sql.Literal(role_pw),
                        )
                    )
                print(
                    "[+] Configured credentials for runtime roles: "
                    "deepfakeshield_app, deepfakeshield_verifier, deepfakeshield_payout_worker, deepfakeshield_auditor."
                )
    except Exception as e:
        print(f"[-] Failed to apply migration: {e}")
        sys.exit(1)

    print("[+] Disposable database setup complete and ready for test execution.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset a disposable DeepfakeShield test database.")
    parser.add_argument(
        "--confirm-drop",
        action="store_true",
        help="Required confirmation to drop and recreate the target disposable database.",
    )
    args = parser.parse_args()
    run_setup(confirm_drop=args.confirm_drop)
