"""Background tasks - Auto-release expired reservations, scheduled backups, expiry notifications."""
import os
import time
import shutil
import threading
from datetime import datetime, timedelta

from app.config import Config


auto_release_active = True


def auto_release_expired_reservations():
    """Background thread: release expired LAN IP reservations every 6 hours."""
    global auto_release_active
    print("Auto-release checker started")

    while auto_release_active:
        try:
            from app.database import get_db, log_audit, create_notification
            conn = get_db()
            conn.row_factory = __import__('sqlite3').Row
            cursor = conn.cursor()

            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute("""
                SELECT id, octet2, octet3, branch_name, username, reservation_date, expiry_date
                FROM reserved_ips WHERE expiry_date < ?
                AND (status = 'reserved' OR status IS NULL)
            """, (today,))
            expired = cursor.fetchall()

            if expired:
                print(f"Found {len(expired)} expired reservations to release")
                for row in expired:
                    cursor.execute("""
                        UPDATE lan_ips SET username=NULL, reservation_date=NULL, branch_name=NULL, status='Free'
                        WHERE octet2=? AND octet3=? AND status='Reserved'
                    """, (row['octet2'], row['octet3']))
                    cursor.execute("DELETE FROM reserved_ips WHERE id=?", (row['id'],))
                    print(f"  Released: 10.{row['octet2']}.{row['octet3']}.0/24 ({row['branch_name']})")

                conn.commit()
                log_audit('auto_release', f'{len(expired)} expired IPs released', 'System', 'system')

            conn.close()

            # Check for soon-expiring reservations and send notifications
            _check_expiry_notifications()

        except Exception as e:
            print(f"Auto-release error: {e}")

        time.sleep(Config.AUTO_RELEASE_INTERVAL)


def _check_expiry_notifications():
    """Send notifications for reservations expiring soon."""
    try:
        from app.database import get_db, create_notification
        conn = get_db()
        conn.row_factory = __import__('sqlite3').Row
        cursor = conn.cursor()

        for days in Config.EXPIRY_WARNING_DAYS:
            target_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
            cursor.execute("""
                SELECT id, octet2, octet3, branch_name, username, expiry_date
                FROM reserved_ips WHERE expiry_date = ?
                AND (status='reserved' OR status IS NULL)
            """, (target_date,))
            for row in cursor.fetchall():
                if row['username']:
                    create_notification(
                        row['username'],
                        f'Reservation expiring in {days} days',
                        f'10.{row["octet2"]}.{row["octet3"]}.0/24 ({row["branch_name"]}) expires on {row["expiry_date"]}',
                        'warning', '/reserve-lan'
                    )
        conn.close()
    except Exception as e:
        print(f"Expiry notification error: {e}")


def scheduled_backup():
    """Background thread: create automatic backups."""
    interval = Config.BACKUP_INTERVAL_HOURS * 3600
    print(f"Scheduled backup started (every {Config.BACKUP_INTERVAL_HOURS}h)")

    while True:
        time.sleep(interval)
        try:
            fname = f'auto_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
            dest = os.path.join(Config.BACKUP_DIR, fname)
            shutil.copy2(Config.DB_PATH, dest)
            size = os.path.getsize(dest)

            from app.database import get_db, log_audit
            conn = get_db()
            conn.execute(
                "INSERT INTO backup_log (filename, created_at, created_by, size_bytes, backup_type) VALUES (?,?,?,?,?)",
                (fname, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'System', size, 'scheduled'))
            conn.commit()
            conn.close()

            log_audit('scheduled_backup', fname, 'System', 'system')
            print(f"Scheduled backup created: {fname} ({size/1024:.1f} KB)")

            # Clean old auto backups (keep last 30)
            _cleanup_old_backups()
        except Exception as e:
            print(f"Scheduled backup error: {e}")


def _cleanup_old_backups():
    """Remove auto backups older than 30 files."""
    try:
        auto_backups = sorted([
            f for f in os.listdir(Config.BACKUP_DIR)
            if f.startswith('auto_backup_') and f.endswith('.db')
        ])
        if len(auto_backups) > 30:
            for old in auto_backups[:-30]:
                os.remove(os.path.join(Config.BACKUP_DIR, old))
    except Exception:
        pass


def start_background_tasks():
    """Start all background threads."""
    global auto_release_active
    auto_release_active = True

    t1 = threading.Thread(target=auto_release_expired_reservations, daemon=True)
    t1.start()
    print("Auto-release thread started (every 6h)")

    t2 = threading.Thread(target=scheduled_backup, daemon=True)
    t2.start()
    print(f"Scheduled backup thread started (every {Config.BACKUP_INTERVAL_HOURS}h)")
