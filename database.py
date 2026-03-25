"""SQLite persistence for parsed archive results."""
import json
import os
import sqlite3
import threading
from dataclasses import asdict
from datetime import datetime

from models import (
    ParseResult, VictimLog, Password, Cookie, AutoFill,
    CreditCard, SystemInfo, CryptoWallet, GrabbedFile, Screenshot,
)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_BASE_DIR, 'data') if os.path.isdir(os.path.join(_BASE_DIR, 'data')) else _BASE_DIR
_DB_PATH = os.path.join(_DATA_DIR, 'stex.db')
_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS archives (
            fkey          TEXT PRIMARY KEY,
            filename      TEXT NOT NULL,
            extract_dir   TEXT,
            result_json   TEXT NOT NULL,
            highlights_json TEXT,
            parsed_at     TEXT NOT NULL
        )
    """)
    conn.commit()


def _result_to_json(result: ParseResult) -> str:
    return json.dumps(asdict(result), ensure_ascii=False)


def _json_to_result(raw: str) -> ParseResult:
    d = json.loads(raw)
    victims = []
    for vd in d.get('victims', []):
        si_data = vd.pop('system_info', None)
        si = None
        if si_data:
            si = SystemInfo(**si_data)

        passwords = [Password(**p) for p in vd.pop('passwords', [])]
        cookies = [Cookie(**c) for c in vd.pop('cookies', [])]
        autofills = [AutoFill(**a) for a in vd.pop('autofills', [])]
        cards = [CreditCard(**c) for c in vd.pop('credit_cards', [])]
        wallets = [CryptoWallet(**w) for w in vd.pop('wallets', [])]
        screenshots = [Screenshot(**s) for s in vd.pop('screenshots', [])]
        grabbed = [GrabbedFile(**g) for g in vd.pop('grabbed_files', [])]

        victims.append(VictimLog(
            folder_name=vd.get('folder_name', ''),
            stealer_type=vd.get('stealer_type', 'Unknown'),
            passwords=passwords,
            cookies=cookies,
            autofills=autofills,
            credit_cards=cards,
            system_info=si,
            wallets=wallets,
            screenshots=screenshots,
            grabbed_files=grabbed,
        ))

    return ParseResult(
        filename=d.get('filename', ''),
        stealer_type=d.get('stealer_type', 'Unknown'),
        victims=victims,
        total_passwords=d.get('total_passwords', 0),
        total_cookies=d.get('total_cookies', 0),
        total_autofills=d.get('total_autofills', 0),
        total_cards=d.get('total_cards', 0),
        total_wallets=d.get('total_wallets', 0),
        total_screenshots=d.get('total_screenshots', 0),
        total_files=d.get('total_files', 0),
        errors=d.get('errors', []),
    )


def save_archive(fkey: str, filename: str, extract_dir: str,
                 result: ParseResult, highlights: dict):
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO archives
           (fkey, filename, extract_dir, result_json, highlights_json, parsed_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (fkey, filename, extract_dir,
         _result_to_json(result),
         json.dumps(highlights, ensure_ascii=False, default=str),
         datetime.utcnow().isoformat()),
    )
    conn.commit()


def delete_archive(fkey: str):
    conn = _get_conn()
    conn.execute("DELETE FROM archives WHERE fkey = ?", (fkey,))
    conn.commit()


def load_all() -> dict[str, dict]:
    """Load all archives from DB. Returns {fkey: {result, extract_dir, highlights}}."""
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM archives").fetchall()
    cache = {}
    for row in rows:
        try:
            result = _json_to_result(row['result_json'])
            hl_raw = row['highlights_json']
            highlights = json.loads(hl_raw) if hl_raw else {}
            cache[row['fkey']] = {
                'result': result,
                'extract_dir': row['extract_dir'] or '',
                'highlights': highlights,
            }
        except Exception:
            continue
    return cache


def archive_exists(fkey: str) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT 1 FROM archives WHERE fkey = ? LIMIT 1", (fkey,)
    ).fetchone()
    return row is not None
