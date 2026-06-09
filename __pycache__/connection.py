"""
db/connection.py — SQLAlchemy engine + session factory.

Usage:
    from db.connection import get_engine, get_session

    with get_session() as session:
        session.execute(text("SELECT 1"))
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise EnvironmentError("DATABASE_URL not set. Copy .env.example → .env and fill it in.")


# connection_args for Supabase (requires SSL); ignored on local Postgres
_connect_args = (
    {"sslmode": "require"} if "supabase.co" in DATABASE_URL else {}
)

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,   # auto-reconnect on stale connections
    echo=False,           # set True to log all SQL (useful for debugging)
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_session() -> Session:
    """Return a context-manager session. Always use inside `with`."""
    return SessionLocal()


def test_connection():
    """Quick smoke test — prints OK or raises."""
    with engine.connect() as conn:
        result = conn.execute(text("SELECT current_database(), version()"))
        db, version = result.fetchone()
        print(f"✅ Connected to: {db}")
        print(f"   {version[:60]}...")


if __name__ == "__main__":
    test_connection()
