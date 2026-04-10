"""
Authentication configuration for the honeypot server.
Reads credentials from .env file.
"""
import hashlib
import hmac
import os
import secrets

from dotenv import load_dotenv

# Load .env from server directory
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

PBKDF2_ITERATIONS = 100_000


def _hash_password(password: str, salt: bytes) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return dk.hex()


def verify_password(plain_password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verify a password against a stored hash using constant-time comparison."""
    salt = bytes.fromhex(salt_hex)
    computed = _hash_password(plain_password, salt)
    return hmac.compare_digest(computed, stored_hash)


def verify_api_key(provided_key: str, stored_key: str) -> bool:
    """Verify an API key using constant-time comparison."""
    if not provided_key or not stored_key:
        return False
    return hmac.compare_digest(provided_key, stored_key)


def load_secrets() -> dict:
    """
    Load auth secrets from environment variables (.env file).
    Required env vars: ADMIN_USERNAME, ADMIN_PASSWORD, API_KEY
    Optional: SESSION_SECRET (auto-generated if not set)
    """
    admin_username = os.environ.get("ADMIN_USERNAME", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    api_key = os.environ.get("API_KEY", "").strip()
    session_secret = os.environ.get("SESSION_SECRET", "").strip()

    if not admin_username or not admin_password or not api_key:
        print("=" * 60)
        print("  ERROR: Missing required environment variables!")
        print("  Please set the following in server/.env:")
        print()
        print("    ADMIN_USERNAME=admin")
        print("    ADMIN_PASSWORD=your_password")
        print("    API_KEY=your_api_key")
        print("    SESSION_SECRET=optional_session_secret")
        print("=" * 60)
        raise SystemExit(1)

    if not session_secret:
        session_secret = secrets.token_hex(32)

    # Hash the password for storage in memory
    salt = secrets.token_bytes(16)

    return {
        "api_key": api_key,
        "admin_username": admin_username,
        "admin_password_hash": _hash_password(admin_password, salt),
        "admin_salt": salt.hex(),
        "session_secret": session_secret,
    }
