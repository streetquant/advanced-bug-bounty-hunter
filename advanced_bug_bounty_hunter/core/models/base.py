"""Database management and base model configuration.

This module provides database connectivity, session management,
and base model classes for the security testing platform.
"""

import asyncio
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, DateTime, Text, Integer
from datetime import datetime

from ..config.settings import DatabaseConfig
from ..utils.logging import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class DatabaseManager:
    """Manages database connections and sessions for the security testing platform."""
    
    def __init__(self, db_config: DatabaseConfig):
        """Initialize the database manager.
        
        Args:
            db_config: Database configuration
        """
        self.config = db_config
        self.engine = None
        self.session_factory = None
        
    async def initialize(self) -> None:
        """Initialize database connection and create tables."""
        logger.info("Initializing database connection")
        
        try:
            # Create async engine
            connection_string = self._get_async_connection_string()
            self.engine = create_async_engine(
                connection_string,
                echo=False,  # Set to True for SQL debugging
                pool_pre_ping=True,
                pool_recycle=3600,
            )
            
            # Create session factory
            self.session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Create all tables
            await self._create_tables()
            
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _get_async_connection_string(self) -> str:
        """Get async database connection string.
        
        Returns:
            Async database connection string
        """
        if self.config.type == "sqlite":
            return f"sqlite+aiosqlite:///{self.config.name}.db"
        elif self.config.type == "postgresql":
            return (
                f"postgresql+asyncpg://{self.config.username}:{self.config.password}"
                f"@{self.config.host}:{self.config.port}/{self.config.name}"
            )
        elif self.config.type == "mysql":
            return (
                f"mysql+aiomysql://{self.config.username}:{self.config.password}"
                f"@{self.config.host}:{self.config.port}/{self.config.name}"
            )
        else:
            raise ValueError(f"Unsupported database type: {self.config.type}")
    
    async def _create_tables(self) -> None:
        """Create all database tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created")
    
    async def get_session(self) -> AsyncSession:
        """Get a new database session.
        
        Returns:
            New async database session
        """
        if not self.session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        return self.session_factory()
    
    async def execute_query(self, query: str, parameters: Optional[dict] = None) -> Any:
        """Execute a raw SQL query.
        
        Args:
            query: SQL query string
            parameters: Optional query parameters
            
        Returns:
            Query result
        """
        async with self.get_session() as session:
            from sqlalchemy import text
            result = await session.execute(text(query), parameters or {})
            await session.commit()
            return result
    
    async def cleanup(self) -> None:
        """Clean up database resources."""
        logger.info("Cleaning up database resources")
        
        try:
            if self.engine:
                await self.engine.dispose()
        except Exception as e:
            logger.warning(f"Error during database cleanup: {e}")
        
        self.engine = None
        self.session_factory = None
        
        logger.info("Database cleanup completed")
