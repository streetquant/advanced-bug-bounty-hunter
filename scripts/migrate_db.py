#!/usr/bin/env python3
"""Database migration script for Advanced Bug Bounty Hunter.

This script handles database initialization, migration, and schema updates
for the security testing platform.
"""

import asyncio
import argparse
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from advanced_bug_bounty_hunter.core.config.config_manager import ConfigManager
from advanced_bug_bounty_hunter.core.models.base import DatabaseManager, Base
from advanced_bug_bounty_hunter.utils.logging import setup_logging, get_logger


async def initialize_database(config_path: str = None) -> None:
    """Initialize the database with all tables.
    
    Args:
        config_path: Optional path to configuration file
    """
    logger = get_logger("migrate_db")
    logger.info("Starting database initialization")
    
    try:
        # Load configuration
        config_manager = ConfigManager(Path(config_path) if config_path else None)
        config = config_manager.load_config()
        
        # Initialize database manager
        db_manager = DatabaseManager(config.database)
        await db_manager.initialize()
        
        logger.info("Database initialization completed successfully")
        
        # Create some initial data if needed
        await create_initial_data(db_manager)
        
        await db_manager.cleanup()
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        raise


async def create_initial_data(db_manager: DatabaseManager) -> None:
    """Create initial data in the database.
    
    Args:
        db_manager: Database manager instance
    """
    logger = get_logger("migrate_db")
    logger.info("Creating initial database data")
    
    # This would create any initial data needed
    # For now, we'll just log that it's ready
    logger.info("Initial data creation completed")


async def drop_all_tables(config_path: str = None) -> None:
    """Drop all database tables (destructive operation).
    
    Args:
        config_path: Optional path to configuration file
    """
    logger = get_logger("migrate_db")
    logger.warning("Dropping all database tables")
    
    try:
        # Load configuration
        config_manager = ConfigManager(Path(config_path) if config_path else None)
        config = config_manager.load_config()
        
        # Create engine and drop all tables
        from sqlalchemy.ext.asyncio import create_async_engine
        
        if config.database.type == "sqlite":
            connection_string = f"sqlite+aiosqlite:///{config.database.name}.db"
        elif config.database.type == "postgresql":
            connection_string = (
                f"postgresql+asyncpg://{config.database.username}:{config.database.password}"
                f"@{config.database.host}:{config.database.port}/{config.database.name}"
            )
        else:
            raise ValueError(f"Unsupported database type: {config.database.type}")
        
        engine = create_async_engine(connection_string)
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        
        await engine.dispose()
        
        logger.info("All database tables dropped successfully")
        
    except Exception as e:
        logger.error(f"Failed to drop database tables: {e}", exc_info=True)
        raise


def main() -> None:
    """Main entry point for the migration script."""
    parser = argparse.ArgumentParser(
        description="Database migration utility for Advanced Bug Bounty Hunter"
    )
    parser.add_argument(
        "--config", 
        "-c",
        help="Path to configuration file (default: config/default.yaml)"
    )
    parser.add_argument(
        "--action",
        "-a",
        choices=["init", "drop", "recreate"],
        default="init",
        help="Migration action to perform (default: init)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set up logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(log_level)
    
    logger = get_logger("migrate_db")
    
    try:
        if args.action == "init":
            logger.info("Initializing database")
            asyncio.run(initialize_database(args.config))
            
        elif args.action == "drop":
            # Confirm destructive operation
            response = input("This will delete ALL data. Are you sure? (yes/no): ")
            if response.lower() == "yes":
                logger.info("Dropping all database tables")
                asyncio.run(drop_all_tables(args.config))
            else:
                logger.info("Operation cancelled")
                
        elif args.action == "recreate":
            # Confirm destructive operation
            response = input("This will delete ALL data and recreate tables. Are you sure? (yes/no): ")
            if response.lower() == "yes":
                logger.info("Recreating database")
                asyncio.run(drop_all_tables(args.config))
                asyncio.run(initialize_database(args.config))
            else:
                logger.info("Operation cancelled")
        
        logger.info("Migration completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Migration interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
