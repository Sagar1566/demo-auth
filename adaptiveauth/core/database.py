"""
AdaptiveAuth Core - Database Module
Database engine, session management, and utilities.
"""
from typing import Generator, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager

from ..config import get_settings
from ..models import Base

# Global variables for database connection
_engine = None
_SessionLocal = None


def get_engine(database_url: Optional[str] = None, echo: bool = False):
    """Get or create database engine."""
    global _engine
    
    if _engine is None:
        settings = get_settings()
        url = database_url or settings.DATABASE_URL
        echo = echo or settings.DATABASE_ECHO
        
        # Configure engine based on database type
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        
        _engine = create_engine(
            url,
            connect_args=connect_args,
            echo=echo,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
    
    return _engine


def get_session_local(database_url: Optional[str] = None):
    """Get or create session factory."""
    global _SessionLocal
    
    if _SessionLocal is None:
        engine = get_engine(database_url)
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine
        )
    
    return _SessionLocal


def init_database(database_url: Optional[str] = None, drop_all: bool = False):
    """Initialize database tables."""
    engine = get_engine(database_url)
    
    if drop_all:
        Base.metadata.drop_all(bind=engine)
    
    Base.metadata.create_all(bind=engine)
    return engine


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database session."""
    SessionLocal = get_session_local()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """Context manager for database session."""
    SessionLocal = get_session_local()
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def reset_database_connection():
    """Reset database connection (useful for testing)."""
    global _engine, _SessionLocal
    
    if _engine:
        _engine.dispose()
    
    _engine = None
    _SessionLocal = None


class DatabaseManager:
    """Database manager for custom configurations."""
    
    def __init__(self, database_url: str, echo: bool = False):
        self.database_url = database_url
        self.echo = echo
        self._engine = None
        self._SessionLocal = None
    
    @property
    def engine(self):
        """Get database engine."""
        if self._engine is None:
            connect_args = {}
            if self.database_url.startswith("sqlite"):
                connect_args["check_same_thread"] = False
            
            self._engine = create_engine(
                self.database_url,
                connect_args=connect_args,
                echo=self.echo,
                pool_pre_ping=True,
            )
        return self._engine
    
    @property
    def session_local(self):
        """Get session factory."""
        if self._SessionLocal is None:
            self._SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
        return self._SessionLocal
    
    def init_tables(self, drop_all: bool = False):
        """Initialize database tables."""
        if drop_all:
            Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self) -> Generator[Session, None, None]:
        """Get database session generator."""
        db = self.session_local()
        try:
            yield db
        finally:
            db.close()
    
    @contextmanager
    def session_scope(self):
        """Context manager for database session."""
        db = self.session_local()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
    
    def close(self):
        """Close database connection."""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._SessionLocal = None
