"""
AdaptiveAuth Core Module
Database, security, and dependency utilities.
"""
from .database import (
    get_db,
    get_db_context,
    get_engine,
    get_session_local,
    init_database,
    reset_database_connection,
    DatabaseManager
)
from .security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_token,
    get_token_expiry,
    generate_token,
    generate_session_token,
    generate_reset_code,
    generate_verification_code,
    generate_device_fingerprint,
    generate_browser_hash,
    hash_token,
    constant_time_compare
)
from .dependencies import (
    get_current_user,
    get_current_user_optional,
    get_current_active_user,
    require_role,
    require_admin,
    require_superadmin,
    get_current_session,
    get_client_info,
    RateLimiter,
    oauth2_scheme
)

__all__ = [
    # Database
    "get_db",
    "get_db_context",
    "get_engine",
    "get_session_local",
    "init_database",
    "reset_database_connection",
    "DatabaseManager",
    # Security
    "hash_password",
    "verify_password",
    "validate_password_strength",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "verify_token",
    "get_token_expiry",
    "generate_token",
    "generate_session_token",
    "generate_reset_code",
    "generate_verification_code",
    "generate_device_fingerprint",
    "generate_browser_hash",
    "hash_token",
    "constant_time_compare",
    # Dependencies
    "get_current_user",
    "get_current_user_optional",
    "get_current_active_user",
    "require_role",
    "require_admin",
    "require_superadmin",
    "get_current_session",
    "get_client_info",
    "RateLimiter",
    "oauth2_scheme",
]
