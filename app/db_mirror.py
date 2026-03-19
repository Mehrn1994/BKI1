"""
Live Database Mirror System
===========================
مشکل: توسعه‌دهنده گاهی network_ipam.db را با نسخه قدیمی جایگزین می‌کند
       و تغییرات تیم از دست می‌رود.

راه‌حل:
  - data/live.db  → دیتابیس فعال سیستم (برنامه همیشه از این می‌خواند/می‌نویسد)
  - data/network_ipam.db → دیتابیس اصلی/رسمی (توسعه‌دهنده مدیریت می‌کند)

عملکرد:
  1. اولین بار: live.db را از network_ipam.db کپی می‌کند
  2. SQLite triggers روی live.db → هر تغییر را در _change_log ثبت می‌کند
  3. هر شب 23:30 → تفاوت‌های live.db را به network_ipam.db اعمال می‌کند
  4. Log قدیمی‌تر از 24 ساعت که merge شده پاک می‌شود
"""

import os
import shutil
import sqlite3
import json
import threading
from datetime import datetime, timedelta

from app.config import Config

# ------------------------------------------------------------------
# paths
# ------------------------------------------------------------------
LIVE_DB_PATH = os.path.join(os.path.dirname(Config.DB_PATH), 'live.db')

# جداولی که تغییرات کاربران روی‌شان ثبت می‌شود
MIRROR_TABLES = [
    'lan_ips', 'apn_ips', 'apn_mali',
    'intranet_tunnels', 'ptmp_connections',
    'reserved_ips', 'tunnel200_ips', 'tunnel_mali',
    'vpls_tunnels', 'user_passwords', 'custom_translations',
    'network_devices',
]

_init_lock = threading.Lock()
_initialized = False


# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------

def ensure_live_db():
    """اطمینان از وجود live.db؛ در صورت نبود از network_ipam.db کپی می‌کند."""
    global _initialized
    with _init_lock:
        if _initialized:
            return
        if not os.path.exists(LIVE_DB_PATH):
            if os.path.exists(Config.DB_PATH):
                print(f"[Mirror] First run — cloning {Config.DB_PATH} → live.db")
                shutil.copy2(Config.DB_PATH, LIVE_DB_PATH)
            else:
                # main DB هم نیست؛ یک فایل خالی می‌سازیم
                open(LIVE_DB_PATH, 'w').close()
        _setup_journal_schema()
        _initialized = True


def _setup_journal_schema():
    """جدول _change_log و تریگرها را در live.db ایجاد می‌کند."""
    conn = sqlite3.connect(LIVE_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS _change_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            table_name TEXT    NOT NULL,
            op         TEXT    NOT NULL,
            row_id     INTEGER NOT NULL,
            row_json   TEXT,
            merged     INTEGER DEFAULT 0,
            merged_at  TEXT
        )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS _idx_cl ON _change_log(merged, ts)"
    )
    conn.commit()

    for table in MIRROR_TABLES:
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,)
            ).fetchone()
            if not exists:
                continue

            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS _trg_{table}_i "
                f"AFTER INSERT ON {table} BEGIN "
                f"INSERT INTO _change_log (table_name, op, row_id) "
                f"VALUES ('{table}', 'I', NEW.id); END"
            )
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS _trg_{table}_u "
                f"AFTER UPDATE ON {table} BEGIN "
                f"INSERT INTO _change_log (table_name, op, row_id) "
                f"VALUES ('{table}', 'U', NEW.id); END"
            )

            # DELETE trigger — snapshot کامل سطر را ذخیره می‌کند
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            json_parts = ", ".join(f"'{c}', OLD.{c}" for c in cols)
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS _trg_{table}_d "
                f"AFTER DELETE ON {table} BEGIN "
                f"INSERT INTO _change_log (table_name, op, row_id, row_json) "
                f"VALUES ('{table}', 'D', OLD.id, json_object({json_parts})); END"
            )

        except Exception as e:
            print(f"[Mirror] Trigger setup for {table}: {e}")

    conn.commit()
    conn.close()
    print(f"[Mirror] live.db ready — triggers active on {len(MIRROR_TABLES)} tables")


# ------------------------------------------------------------------
# merge
# ------------------------------------------------------------------

def merge_live_to_main(dry_run=False):
    """
    تمام تغییرات ثبت‌نشده live.db را به network_ipam.db اعمال می‌کند.
    برمی‌گرداند: dict با خلاصه نتیجه
    """
    ensure_live_db()

    live = sqlite3.connect(LIVE_DB_PATH)
    live.row_factory = sqlite3.Row
    main = sqlite3.connect(Config.DB_PATH)
    main.row_factory = sqlite3.Row

    pending = live.execute(
        "SELECT * FROM _change_log WHERE merged=0 ORDER BY id ASC"
    ).fetchall()

    stats = {
        'total': len(pending),
        'applied': 0,
        'skipped': 0,
        'errors': 0,
        'dry_run': dry_run,
        'detail': [],
        'ts': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    merged_ids = []

    for ch in pending:
        table = ch['table_name']
        op    = ch['op']
        rid   = ch['row_id']

        try:
            if op == 'D':
                if not dry_run:
                    main.execute(f"DELETE FROM {table} WHERE id=?", (rid,))
                stats['applied'] += 1
                stats['detail'].append(f"DELETE {table} id={rid}")

            elif op in ('I', 'U'):
                live_row = live.execute(
                    f"SELECT * FROM {table} WHERE id=?", (rid,)
                ).fetchone()

                if live_row is None:
                    # سطر دیگر در live.db نیست (احتمالاً بعداً حذف شده)
                    stats['skipped'] += 1
                    continue

                data = dict(live_row)
                cols = list(data.keys())
                exists_in_main = main.execute(
                    f"SELECT id FROM {table} WHERE id=?", (rid,)
                ).fetchone()

                if not dry_run:
                    if exists_in_main:
                        non_id = [c for c in cols if c != 'id']
                        set_sql = ', '.join(f"{c}=?" for c in non_id)
                        vals = [data[c] for c in non_id] + [rid]
                        main.execute(f"UPDATE {table} SET {set_sql} WHERE id=?", vals)
                    else:
                        ph = ','.join('?' * len(cols))
                        main.execute(
                            f"INSERT OR REPLACE INTO {table} "
                            f"({','.join(cols)}) VALUES ({ph})",
                            [data[c] for c in cols]
                        )

                stats['applied'] += 1
                stats['detail'].append(f"{op} {table} id={rid}")

            merged_ids.append(ch['id'])

        except Exception as e:
            stats['errors'] += 1
            stats['detail'].append(f"ERROR {table} id={rid}: {e}")
            print(f"[Mirror] merge error on {table} id={rid}: {e}")

    if not dry_run:
        if stats['errors'] == 0:
            main.commit()
        else:
            main.rollback()

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if merged_ids:
            live.execute(
                f"UPDATE _change_log SET merged=1, merged_at=? "
                f"WHERE id IN ({','.join('?'*len(merged_ids))})",
                [now_str] + merged_ids
            )
        # پاک‌سازی log های قدیمی (merge شده و قدیمی‌تر از 24 ساعت)
        live.execute("""
            DELETE FROM _change_log
            WHERE merged=1
              AND ts < datetime('now', '-24 hours', 'localtime')
        """)
        live.commit()

    main.close()
    live.close()
    return stats


# ------------------------------------------------------------------
# status
# ------------------------------------------------------------------

def get_status():
    """وضعیت فعلی mirror را برمی‌گرداند."""
    ensure_live_db()
    try:
        conn = sqlite3.connect(LIVE_DB_PATH)
        pending = conn.execute(
            "SELECT COUNT(*) FROM _change_log WHERE merged=0"
        ).fetchone()[0]
        total = conn.execute(
            "SELECT COUNT(*) FROM _change_log"
        ).fetchone()[0]
        last_merged = conn.execute(
            "SELECT MAX(merged_at) FROM _change_log WHERE merged=1"
        ).fetchone()[0]
        oldest = conn.execute(
            "SELECT MIN(ts) FROM _change_log WHERE merged=0"
        ).fetchone()[0]
        by_table = conn.execute("""
            SELECT table_name, COUNT(*) AS cnt
            FROM _change_log WHERE merged=0
            GROUP BY table_name ORDER BY cnt DESC
        """).fetchall()

        # آخرین merge از merge_log
        last_merge_log = None
        try:
            last_merge_log = conn.execute(
                "SELECT MAX(ts) FROM _merge_log"
            ).fetchone()[0]
        except Exception:
            pass

        conn.close()

        live_size  = os.path.getsize(LIVE_DB_PATH) if os.path.exists(LIVE_DB_PATH) else 0
        main_size  = os.path.getsize(Config.DB_PATH) if os.path.exists(Config.DB_PATH) else 0

        return {
            'live_db':          LIVE_DB_PATH,
            'main_db':          Config.DB_PATH,
            'live_size_kb':     round(live_size / 1024, 1),
            'main_size_kb':     round(main_size / 1024, 1),
            'pending_changes':  pending,
            'total_logged':     total,
            'last_merged_at':   last_merged,
            'oldest_pending':   oldest,
            'by_table':         {r[0]: r[1] for r in by_table},
            'last_merge_run':   last_merge_log,
        }
    except Exception as e:
        return {'error': str(e)}


def _log_merge_run(stats):
    """نتیجه merge را در live.db ثبت می‌کند (برای تاریخچه)."""
    try:
        conn = sqlite3.connect(LIVE_DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS _merge_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT DEFAULT CURRENT_TIMESTAMP,
                applied  INTEGER,
                skipped  INTEGER,
                errors   INTEGER,
                dry_run  INTEGER,
                detail   TEXT
            )""")
        conn.execute(
            "INSERT INTO _merge_log (applied, skipped, errors, dry_run, detail) "
            "VALUES (?,?,?,?,?)",
            (stats['applied'], stats['skipped'], stats['errors'],
             1 if stats['dry_run'] else 0,
             json.dumps(stats['detail'], ensure_ascii=False))
        )
        # فقط 100 رکورد آخر را نگه می‌داریم
        conn.execute(
            "DELETE FROM _merge_log WHERE id NOT IN "
            "(SELECT id FROM _merge_log ORDER BY id DESC LIMIT 100)"
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Mirror] _log_merge_run error: {e}")
