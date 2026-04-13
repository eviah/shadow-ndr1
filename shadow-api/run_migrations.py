#!/usr/bin/env python3
"""
Shadow NDR Database Migration Runner
Executes SQL migrations against PostgreSQL
"""

import asyncio
import sys
from pathlib import Path

import asyncpg
from loguru import logger

# Configure logging
logger.remove()
logger.add(sys.stderr, level="INFO", format="<level>{level: <8}</level> | {message}")


async def run_migrations():
    """Run all pending database migrations."""
    
    # Database configuration
    db_config = {
        "host": "localhost",
        "port": 5432,
        "user": "postgres",
        "password": "shadow123",
        "database": "shadow",
        "command_timeout": 60,
    }
    
    try:
        # Connect to database
        logger.info("Connecting to PostgreSQL...")
        conn = await asyncpg.connect(**db_config)
        logger.info(f"✅ Connected to {db_config['database']}")
        
        # Get migrations directory
        migrations_dir = Path(__file__).parent / "migrations"
        if not migrations_dir.exists():
            logger.warning(f"Migrations directory not found: {migrations_dir}")
            return
        
        # Get all SQL migration files
        migration_files = sorted(migrations_dir.glob("*.sql"))
        if not migration_files:
            logger.info("No migrations to run")
            return
        
        # Execute each migration
        for migration_file in migration_files:
            logger.info(f"Running migration: {migration_file.name}")
            
            try:
                sql_content = migration_file.read_text(encoding="utf-8")
                await conn.execute(sql_content)
                logger.info(f"✅ Migration complete: {migration_file.name}")
            except Exception as e:
                logger.error(f"❌ Migration failed: {migration_file.name}")
                logger.error(f"Error: {e}")
                await conn.close()
                raise
        
        # Verify tables were created
        logger.info("Verifying tables...")
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name;
        """)
        
        logger.info("Tables in database:")
        for table in tables:
            logger.info(f"  - {table['table_name']}")
        
        # Count records
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
        logger.info(f"Users in database: {user_count}")
        
        await conn.close()
        logger.info("✅ All migrations completed successfully!")
        
    except asyncpg.PostgresError as e:
        logger.error(f"PostgreSQL Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_migrations())
