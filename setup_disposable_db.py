#!/usr/bin/env python3
"""
DeepfakeShield for PayPal — Disposable Database Setup Script
Milestone: V10.1.3 — Migration and Security Repair
Target: PostgreSQL 18.6

Connects using environment-provided or default credentials, drops and recreates
the disposable test database deepfakeshield_db, applies V10_1_3__security_repair.sql,
and configures credentials for all runtime roles.
"""

import os
import sys
import psycopg

def get_env_config():
    return {
        "host": os.environ.get("PGHOST", "127.0.0.1"),
        "port": int(os.environ.get("PGPORT", "5433")),
        "admin_user": os.environ.get("PGUSER", "postgres"),
        "admin_password": os.environ.get("PGPASSWORD", "postgres"),
        "database": os.environ.get("PGDATABASE", "deepfakeshield_db"),
        "app_password": os.environ.get("APP_PASSWORD", "app_secret_pass"),
        "verifier_password": os.environ.get("VERIFIER_PASSWORD", "verifier_secret_pass"),
        "worker_password": os.environ.get("WORKER_PASSWORD", "worker_secret_pass"),
        "auditor_password": os.environ.get("AUDITOR_PASSWORD", "auditor_secret_pass"),
    }

def run_setup():
    cfg = get_env_config()
    print(f"[*] Initializing disposable PostgreSQL 18 database setup on {cfg['host']}:{cfg['port']}...")

    # Step 1: Connect to maintenance db (postgres) as superuser to drop & recreate target db
    maint_conn_str = f"host={cfg['host']} port={cfg['port']} dbname=postgres user={cfg['admin_user']} password={cfg['admin_password']}"
    try:
        with psycopg.connect(maint_conn_str, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS {cfg['database']} WITH (FORCE);")
                cur.execute(f"CREATE DATABASE {cfg['database']};")
                print(f"[+] Successfully recreated database '{cfg['database']}'.")
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

    target_conn_str = f"host={cfg['host']} port={cfg['port']} dbname={cfg['database']} user={cfg['admin_user']} password={cfg['admin_password']}"
    try:
        with psycopg.connect(target_conn_str, autocommit=True) as conn:
            with conn.cursor() as cur:
                print(f"[*] Applying migration: V10_1_3__security_repair.sql...")
                cur.execute(migration_sql)
                print(f"[+] Successfully applied V10_1_3__security_repair.sql.")

                # Step 3: Configure credentials for runtime test roles
                cur.execute(f"ALTER ROLE deepfakeshield_app WITH PASSWORD '{cfg['app_password']}';")
                cur.execute(f"ALTER ROLE deepfakeshield_verifier WITH PASSWORD '{cfg['verifier_password']}';")
                cur.execute(f"ALTER ROLE deepfakeshield_payout_worker WITH PASSWORD '{cfg['worker_password']}';")
                cur.execute(f"ALTER ROLE deepfakeshield_auditor WITH PASSWORD '{cfg['auditor_password']}';")
                print(f"[+] Configured credentials for runtime roles: deepfakeshield_app, deepfakeshield_verifier, deepfakeshield_payout_worker, deepfakeshield_auditor.")
    except Exception as e:
        print(f"[-] Failed to apply migration: {e}")
        sys.exit(1)

    print("[+] Disposable database setup complete and ready for test execution.")

if __name__ == "__main__":
    run_setup()
