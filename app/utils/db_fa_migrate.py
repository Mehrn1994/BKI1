"""
Database migration: add *_fa columns to all tables that store branch/province names
and bulk-translate existing English data to Persian.

Safe to run multiple times (idempotent).
"""

import sqlite3
import logging

log = logging.getLogger(__name__)

# Table → list of (english_col, persian_col) pairs to add & populate
FA_COLUMNS = {
    'lan_ips': [
        ('branch_name', 'branch_name_fa'),
        ('province',    'province_fa'),
    ],
    'reserved_ips': [
        ('branch_name', 'branch_name_fa'),
        ('province',    'province_fa'),
    ],
    'apn_ips': [
        ('branch_name', 'branch_name_fa'),
        ('province',    'province_fa'),
    ],
    'apn_mali': [
        ('branch_name', 'branch_name_fa'),
        ('province',    'province_fa'),
    ],
    'intranet_tunnels': [
        ('tunnel_name', 'tunnel_name_fa'),
        ('description', 'description_fa'),
        ('province',    'province_fa'),
    ],
    'vpls_tunnels': [
        ('branch_name', 'branch_name_fa'),
        ('description', 'description_fa'),
        ('province',    'province_fa'),
    ],
    'ptmp_connections': [
        ('branch_name', 'branch_name_fa'),
        ('province',    'province_fa'),
    ],
    'tunnel_mali': [
        ('branch_name',  'branch_name_fa'),
        ('description',  'description_fa'),
    ],
    'tunnel200_ips': [
        ('branch_name',  'branch_name_fa'),
        ('description',  'description_fa'),
    ],
}

# Province columns get translate_province() instead of translate()
_PROVINCE_COLS = {'province_fa'}


def _col_exists(cursor, table: str, col: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == col for row in cursor.fetchall())


def run_migration(db_path: str) -> dict:
    """
    1. Add _fa columns where missing (ALTER TABLE).
    2. Bulk-translate all rows whose _en col is non-empty but _fa col is NULL/empty.

    Returns a summary dict: {table: {added_cols, rows_translated}}.
    """
    # Import here to avoid circular imports at module load time
    from app.utils.translator import translate, translate_province, load_custom_from_db

    summary = {}
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Load user custom translations first
    load_custom_from_db(conn)

    for table, col_pairs in FA_COLUMNS.items():
        summary[table] = {'added_cols': [], 'rows_translated': 0}

        # Check table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        if not cursor.fetchone():
            continue

        # Step 1: Add missing _fa columns
        for _en_col, fa_col in col_pairs:
            if not _col_exists(cursor, table, fa_col):
                try:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {fa_col} TEXT")
                    conn.commit()
                    summary[table]['added_cols'].append(fa_col)
                    log.info(f"Added column {table}.{fa_col}")
                except Exception as e:
                    log.warning(f"Could not add {table}.{fa_col}: {e}")

        # Step 2: Translate existing rows that have English value but no Persian value
        for en_col, fa_col in col_pairs:
            if not _col_exists(cursor, table, en_col) or not _col_exists(cursor, table, fa_col):
                continue

            # Fetch rows that need translation
            try:
                cursor.execute(f"""
                    SELECT rowid, {en_col} FROM {table}
                    WHERE ({en_col} IS NOT NULL AND {en_col} != '')
                      AND ({fa_col} IS NULL OR {fa_col} = '')
                    LIMIT 5000
                """)
                rows = cursor.fetchall()
            except Exception as e:
                log.warning(f"Could not fetch {table}.{en_col}: {e}")
                continue

            if not rows:
                continue

            translator_fn = translate_province if fa_col in _PROVINCE_COLS else translate
            updates = []
            for row in rows:
                en_val = row[1]
                if not en_val:
                    continue
                fa_val = translator_fn(en_val)
                if fa_val and fa_val != en_val:
                    updates.append((fa_val, row[0]))

            if updates:
                try:
                    cursor.executemany(
                        f"UPDATE {table} SET {fa_col} = ? WHERE rowid = ?",
                        updates
                    )
                    conn.commit()
                    summary[table]['rows_translated'] += len(updates)
                    log.info(f"Translated {len(updates)} rows in {table}.{fa_col}")
                except Exception as e:
                    conn.rollback()
                    log.error(f"Error updating {table}.{fa_col}: {e}")

    conn.close()
    return summary


def translate_on_save(db_path: str, table: str, rowid: int) -> None:
    """
    Translate _fa columns for a single row right after INSERT/UPDATE.
    Call this from route handlers after saving.
    """
    if table not in FA_COLUMNS:
        return
    from app.utils.translator import translate, translate_province

    col_pairs = FA_COLUMNS[table]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Fetch current values
        cols = ', '.join(en for en, _ in col_pairs)
        cursor.execute(f"SELECT {cols} FROM {table} WHERE rowid = ?", (rowid,))
        row = cursor.fetchone()
        if not row:
            return

        updates = {}
        for i, (en_col, fa_col) in enumerate(col_pairs):
            en_val = row[i]
            if not en_val:
                continue
            translator_fn = translate_province if fa_col in _PROVINCE_COLS else translate
            fa_val = translator_fn(en_val)
            if fa_val and fa_val != en_val:
                updates[fa_col] = fa_val

        if updates:
            set_clause = ', '.join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [rowid]
            cursor.execute(f"UPDATE {table} SET {set_clause} WHERE rowid = ?", values)
            conn.commit()
    except Exception as e:
        log.warning(f"translate_on_save error ({table}#{rowid}): {e}")
    finally:
        conn.close()
