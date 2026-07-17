# ============================================================
# GuardianHer AI — database/connection.py
#
# Singleton database connection manager.
#
# Design decisions:
#   1. DatabaseManager is a thread-safe singleton. Every part
#      of the application shares the same instance, obtained
#      via DatabaseManager.get_instance().
#
#   2. Connection is lazily opened on first use and kept open
#      for the lifetime of the process (Streamlit runs as a
#      single long-lived process per user session).
#
#   3. WAL (Write-Ahead Logging) mode is enabled to allow
#      concurrent reads while a write is in progress — critical
#      for the biometric monitor page reading data while an SOS
#      event is being written simultaneously.
#
#   4. context manager support:
#         with db.get_cursor() as cursor:
#             cursor.execute(...)
#      Commits on success, rolls back on exception.
#
#   5. Production swap path: replace the sqlite3 import and
#      _open_connection() body with ibm_db_dbi equivalents.
#      All repository code above this layer is unchanged.
#
# Usage:
#   from database.connection import DatabaseManager
#   db = DatabaseManager.get_instance()
#   with db.get_cursor() as cur:
#       cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
#       row = cur.fetchone()
# ============================================================

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Generator, Optional

from config.constants import DatabaseConfig
from config.settings import settings

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Row factory — returns dicts instead of plain tuples
# ─────────────────────────────────────────────────────────────

def _dict_row_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    """
    SQLite row_factory that converts every row to a plain dict.
    Column names become keys, making repository code read like:
        user["name"]  instead of  row[2]
    """
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


# ─────────────────────────────────────────────────────────────
# DatabaseManager — singleton
# ─────────────────────────────────────────────────────────────

class DatabaseManager:
    """
    Thread-safe singleton that owns the SQLite connection for
    the lifetime of the Streamlit process.

    All repositories obtain a cursor through get_cursor() and
    never hold a reference to the connection directly.
    """

    _instance: Optional["DatabaseManager"] = None
    _lock: threading.Lock = threading.Lock()

    # ── Singleton accessor ───────────────────────────────────

    @classmethod
    def get_instance(cls) -> "DatabaseManager":
        """
        Return the singleton instance, creating it on first call.
        Thread-safe via double-checked locking.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Constructor ──────────────────────────────────────────

    def __init__(self) -> None:
        """
        Private — use get_instance() instead.
        Raises RuntimeError if called a second time.
        """
        if DatabaseManager._instance is not None:
            raise RuntimeError(
                "DatabaseManager is a singleton. Use DatabaseManager.get_instance()."
            )
        self._connection: Optional[sqlite3.Connection] = None
        self._db_path: str = settings.DATABASE_PATH
        self._write_lock = threading.Lock()
        self._ensure_data_directory()

    # ── Private helpers ──────────────────────────────────────

    def _ensure_data_directory(self) -> None:
        """Create the data/ directory if it does not exist."""
        directory = os.path.dirname(os.path.abspath(self._db_path))
        os.makedirs(directory, exist_ok=True)

    def _open_connection(self) -> sqlite3.Connection:
        """
        Open and configure the SQLite connection.

        Configuration applied:
          - WAL journal mode   → concurrent read/write
          - Foreign keys ON    → FK constraints enforced
          - Busy timeout       → wait instead of immediate SQLITE_BUSY
          - Row factory        → rows returned as dicts
          - check_same_thread=False → safe for Streamlit's threading model

        Production swap: replace this method's body with:
            import ibm_db_dbi
            conn = ibm_db_dbi.connect(settings.DATABASE_URL, "", "")
            return conn
        All code above this point is unchanged.
        """
        logger.info("[DB] Opening SQLite connection: %s", self._db_path)
        conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,   # Streamlit runs callbacks in threads
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.row_factory = _dict_row_factory

        if DatabaseConfig.WAL_MODE:
            conn.execute("PRAGMA journal_mode = WAL;")

        if DatabaseConfig.FOREIGN_KEYS:
            conn.execute("PRAGMA foreign_keys = ON;")

        conn.execute(f"PRAGMA busy_timeout = {DatabaseConfig.BUSY_TIMEOUT_MS};")

        # Optimise for read-heavy Streamlit workloads
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = -32000;")   # 32 MB page cache
        conn.execute("PRAGMA temp_store = MEMORY;")

        logger.debug("[DB] SQLite PRAGMAs applied (WAL=%s, FK=%s).",
                     DatabaseConfig.WAL_MODE, DatabaseConfig.FOREIGN_KEYS)
        return conn

    # ── Public connection accessor ───────────────────────────

    @property
    def connection(self) -> sqlite3.Connection:
        """
        Return the open connection, opening it lazily on first access.
        If the connection was closed (e.g., process restart), it is
        re-opened transparently.
        """
        if self._connection is None:
            self._connection = self._open_connection()
        else:
            # Verify connection is still alive
            try:
                self._connection.execute("SELECT 1")
            except sqlite3.ProgrammingError:
                logger.warning("[DB] Connection was closed. Re-opening.")
                self._connection = self._open_connection()
        return self._connection

    # ── Context manager for cursor + transaction ─────────────

    @contextmanager
    def get_cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        """
        Context manager that yields a cursor and manages the transaction.

        On normal exit:   COMMIT
        On exception:     ROLLBACK  (then re-raises the exception)

        Write operations acquire _write_lock to serialise concurrent
        writes (SQLite WAL mode supports 1 writer at a time).

        Usage:
            with db.get_cursor() as cur:
                cur.execute("INSERT INTO users ...", (...))
                # auto-committed on exit
        """
        with self._write_lock:
            cursor = self.connection.cursor()
            try:
                yield cursor
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                logger.exception("[DB] Transaction rolled back due to exception.")
                raise
            finally:
                cursor.close()

    @contextmanager
    def get_read_cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        """
        Context manager for read-only queries.
        Does NOT acquire the write lock — allows concurrent reads.
        Does NOT commit or rollback (SELECT has no side effects).

        Usage:
            with db.get_read_cursor() as cur:
                cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
                row = cur.fetchone()
        """
        cursor = self.connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    # ── Health check ─────────────────────────────────────────

    def ping(self) -> bool:
        """
        Return True if the database connection is healthy.
        Used by app.py startup validation.
        """
        try:
            with self.get_read_cursor() as cur:
                cur.execute("SELECT 1")
            return True
        except Exception as exc:
            logger.error("[DB] Health check failed: %s", exc)
            return False

    # ── Graceful shutdown ────────────────────────────────────

    def close(self) -> None:
        """
        Close the database connection.
        Called on application shutdown (Streamlit atexit hook in app.py).
        """
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.info("[DB] Connection closed.")

    # ── repr ─────────────────────────────────────────────────

    def __repr__(self) -> str:
        status = "open" if self._connection else "closed"
        return f"<DatabaseManager path={self._db_path!r} status={status}>"


# ─────────────────────────────────────────────────────────────
# Module-level convenience accessor
# ─────────────────────────────────────────────────────────────

def get_db() -> DatabaseManager:
    """
    Module-level shorthand for DatabaseManager.get_instance().
    Used by all repository files:

        from database.connection import get_db
        db = get_db()
    """
    return DatabaseManager.get_instance()
