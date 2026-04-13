#!/usr/bin/env python3
"""
Shadow NDR - Database Migration Script
Creates users, password_resets, and auth_logs tables
"""

import asyncio
import asyncpg
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import get_settings

SQL_STATEMENTS = [
    # Users table
    """
    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        org_id TEXT NOT NULL DEFAULT 'default',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        is_active BOOLEAN NOT NULL DEFAULT true
    );
    """,
    
    # Password reset tokens
    """
    CREATE TABLE IF NOT EXISTS password_resets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    
    # Authentication audit log
    """
    CREATE TABLE IF NOT EXISTS auth_logs (
        id BIGSERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        success BOOLEAN NOT NULL,
        ip TEXT,
        user_agent TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    
    # Indexes
    """CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);""",
    """CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);""",
    """CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);""",
    """CREATE INDEX IF NOT EXISTS idx_auth_logs_username ON auth_logs(username);""",
]


async def migrate():
    """Execute all migrations."""
    settings = get_settings()
    db_config = settings.database
    
    print("🔗 Connecting to PostgreSQL...")
    print(f"   Host: {db_config.host}:{db_config.port}")
    print(f"   Database: {db_config.database}")
    print(f"   User: {db_config.user}")
    
    try:
        conn = await asyncpg.connect(
            host=db_config.host,
            port=db_config.port,
            user=db_config.user,
            password=db_config.password.get_secret_value(),
            database=db_config.database,
            timeout=db_config.connect_timeout,
            ssl=db_config.ssl_mode if db_config.ssl_mode != "disable" else None,
        )
        
        print("✅ Connected successfully!\n")
        
        # Execute each statement
        for i, sql in enumerate(SQL_STATEMENTS, 1):
            try:
                await conn.execute(sql)
                print(f"✅ Step {i}/{len(SQL_STATEMENTS)}: OK")
            except Exception as e:
                print(f"❌ Step {i}/{len(SQL_STATEMENTS)}: FAILED")
                print(f"   Error: {e}")
                await conn.close()
                return False
        
        await conn.close()
        print("\n✅ All migrations completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False


if __name__ == "__main__":
    success = asyncio.run(migrate())
    sys.exit(0 if success else 1)
