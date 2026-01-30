"""
Secure session management for Monarch Money MCP Server.
Uses keyring (local dev) with file-based fallback (containers/deployment).
"""

import asyncio
import json
import logging
import os
import traceback
from pathlib import Path
from typing import Optional, Tuple
from monarchmoney import MonarchMoney

logger = logging.getLogger(__name__)

# PATCH: Monarch Money changed their API endpoint (see https://github.com/hammem/monarchmoney/issues/179)
# Note: BASE_URL is on MonarchMoneyEndpoints class, not MonarchMoney
from monarchmoney.monarchmoney import MonarchMoneyEndpoints
MonarchMoneyEndpoints.BASE_URL = "https://api.monarch.com"

# Keyring service identifiers (used when keyring is available)
KEYRING_SERVICE = "com.mcp.monarch-mcp-server"
KEYRING_USERNAME = "monarch-token"
KEYRING_EMAIL = "monarch-email"
KEYRING_PASSWORD = "monarch-password"
KEYRING_MFA_SECRET = "monarch-mfa-secret"

# File-based storage (used in containers / when keyring unavailable)
DATA_DIR = Path(os.environ.get("MONARCH_DATA_DIR", "/data"))
CREDENTIALS_FILE = "monarch_credentials.json"


def _keyring_available() -> bool:
    """Check if system keyring is available (not in container)."""
    try:
        import keyring
        # Try a harmless read to verify keyring backend works
        keyring.get_password(KEYRING_SERVICE, "__test__")
        return True
    except Exception:
        return False


# Determine storage backend at import time
USE_KEYRING = _keyring_available()
if USE_KEYRING:
    import keyring
    logger.info("🔑 Using system keyring for credential storage")
else:
    logger.info("📁 Using file-based credential storage (keyring unavailable)")


class SecureMonarchSession:
    """Manages Monarch Money sessions using keyring or file-based storage."""

    # ========================================================================
    # File-based storage helpers
    # ========================================================================

    def _get_credentials_path(self) -> Path:
        """Get path to credentials file, creating directory if needed."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        return DATA_DIR / CREDENTIALS_FILE

    def _read_file_store(self) -> dict:
        """Read credentials from file storage."""
        path = self._get_credentials_path()
        if path.exists():
            try:
                return json.loads(path.read_text())
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"❌ Failed to read credentials file: {e}")
        return {}

    def _write_file_store(self, data: dict) -> None:
        """Write credentials to file storage."""
        path = self._get_credentials_path()
        try:
            path.write_text(json.dumps(data))
            # Restrict permissions to owner only
            path.chmod(0o600)
            logger.debug("📁 Credentials written to file store")
        except OSError as e:
            logger.error(f"❌ Failed to write credentials file: {e}")
            raise

    # ========================================================================
    # Credential operations (keyring or file-based)
    # ========================================================================

    def save_credentials(self, email: str, password: str, mfa_secret: Optional[str] = None) -> None:
        """Save email, password, and optionally MFA secret."""
        if USE_KEYRING:
            try:
                keyring.set_password(KEYRING_SERVICE, KEYRING_EMAIL, email)
                keyring.set_password(KEYRING_SERVICE, KEYRING_PASSWORD, password)
                if mfa_secret:
                    keyring.set_password(KEYRING_SERVICE, KEYRING_MFA_SECRET, mfa_secret)
                logger.info("✅ Credentials saved to keyring")
                return
            except Exception as e:
                logger.error(f"❌ Keyring save failed: {e}")
                raise

        # File-based fallback
        store = self._read_file_store()
        store["email"] = email
        store["password"] = password
        if mfa_secret:
            store["mfa_secret"] = mfa_secret
        self._write_file_store(store)
        logger.info("✅ Credentials saved to file store")

    def save_mfa_secret(self, mfa_secret: str) -> None:
        """Save MFA secret key."""
        if USE_KEYRING:
            keyring.set_password(KEYRING_SERVICE, KEYRING_MFA_SECRET, mfa_secret)
            logger.info("✅ MFA secret saved to keyring")
        else:
            store = self._read_file_store()
            store["mfa_secret"] = mfa_secret
            self._write_file_store(store)
            logger.info("✅ MFA secret saved to file store")

    def load_credentials(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Load email, password, and MFA secret."""
        if USE_KEYRING:
            try:
                logger.debug("🔍 Loading credentials from keyring...")
                email = keyring.get_password(KEYRING_SERVICE, KEYRING_EMAIL)
                password = keyring.get_password(KEYRING_SERVICE, KEYRING_PASSWORD)
                mfa_secret = keyring.get_password(KEYRING_SERVICE, KEYRING_MFA_SECRET)
                logger.debug(f"🔍 Credentials: email={'yes' if email else 'no'}, password={'yes' if password else 'no'}, mfa={'yes' if mfa_secret else 'no'}")
                if email and password:
                    logger.info("✅ Credentials loaded from keyring")
                return email, password, mfa_secret
            except Exception as e:
                logger.error(f"❌ Failed to load from keyring: {e}")
                return None, None, None

        # File-based fallback
        store = self._read_file_store()
        email = store.get("email")
        password = store.get("password")
        mfa_secret = store.get("mfa_secret")
        logger.debug(f"🔍 File store credentials: email={'yes' if email else 'no'}, password={'yes' if password else 'no'}, mfa={'yes' if mfa_secret else 'no'}")
        if email and password:
            logger.info("✅ Credentials loaded from file store")
        return email, password, mfa_secret

    def delete_credentials(self) -> None:
        """Delete stored credentials."""
        if USE_KEYRING:
            for key in [KEYRING_EMAIL, KEYRING_PASSWORD, KEYRING_MFA_SECRET]:
                try:
                    keyring.delete_password(KEYRING_SERVICE, key)
                except Exception:
                    pass
            logger.info("🗑️ Credentials deleted from keyring")
        else:
            store = self._read_file_store()
            for key in ["email", "password", "mfa_secret"]:
                store.pop(key, None)
            self._write_file_store(store)
            logger.info("🗑️ Credentials deleted from file store")

    # ========================================================================
    # Token operations
    # ========================================================================

    def save_token(self, token: str) -> None:
        """Save the authentication token."""
        if USE_KEYRING:
            try:
                keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, token)
                logger.info("✅ Token saved to keyring")
                self._cleanup_old_session_files()
                return
            except Exception as e:
                logger.error(f"❌ Keyring save failed: {e}")
                raise

        # File-based fallback
        store = self._read_file_store()
        store["token"] = token
        self._write_file_store(store)
        logger.info("✅ Token saved to file store")

    def load_token(self) -> Optional[str]:
        """Load the authentication token."""
        if USE_KEYRING:
            try:
                logger.debug(f"🔍 load_token() - keyring.get_password({KEYRING_SERVICE}, {KEYRING_USERNAME})")
                token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
                if token:
                    logger.info(f"✅ Token loaded from keyring (length: {len(token)})")
                else:
                    logger.info("🔍 No token found in keyring")
                return token
            except Exception as e:
                logger.error(f"❌ Failed to load token from keyring: {e}")
                return None

        # File-based fallback
        store = self._read_file_store()
        token = store.get("token")
        if token:
            logger.info(f"✅ Token loaded from file store (length: {len(token)})")
        else:
            logger.info("🔍 No token found in file store")
        return token

    def delete_token(self) -> None:
        """Delete the authentication token."""
        if USE_KEYRING:
            try:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
                logger.info("🗑️ Token deleted from keyring")
                self._cleanup_old_session_files()
            except Exception:
                logger.info("🔍 No token found in keyring to delete")
            return

        # File-based fallback
        store = self._read_file_store()
        store.pop("token", None)
        self._write_file_store(store)
        logger.info("🗑️ Token deleted from file store")

    # ========================================================================
    # Client operations
    # ========================================================================

    def get_authenticated_client(self) -> Optional[MonarchMoney]:
        """Get an authenticated MonarchMoney client."""
        logger.debug("🔍 get_authenticated_client() called")
        token = self.load_token()
        logger.debug(f"🔍 Token loaded: {'yes (len=' + str(len(token)) + ')' if token else 'no'}")
        if not token:
            return None

        try:
            client = MonarchMoney(token=token)
            logger.info("✅ MonarchMoney client created with stored token")
            return client
        except Exception as e:
            logger.error(f"❌ Failed to create MonarchMoney client: {type(e).__name__}: {e}")
            return None

    def save_authenticated_session(self, mm: MonarchMoney) -> None:
        """Save the session from an authenticated MonarchMoney instance."""
        if mm.token:
            self.save_token(mm.token)
        else:
            logger.warning("⚠️  MonarchMoney instance has no token to save")

    async def reauthenticate(self, max_retries: int = 3) -> Optional[MonarchMoney]:
        """Re-authenticate using stored credentials (including MFA secret if available)."""
        logger.debug("🔍 reauthenticate() called")
        email, password, mfa_secret = self.load_credentials()
        if not email or not password:
            logger.warning("⚠️  No stored credentials for re-authentication")
            return None

        last_error = None
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    wait_time = 2 ** attempt
                    logger.info(f"🔄 Retry {attempt + 1}/{max_retries} after {wait_time}s...")
                    await asyncio.sleep(wait_time)

                logger.info("🔄 Attempting re-authentication with stored credentials...")
                client = MonarchMoney()

                # save_session=False prevents monarchmoney from creating .mm/ directory
                if mfa_secret:
                    logger.info("🔐 Using stored MFA secret for authentication")
                    logger.debug(f"🔍 Calling client.login with email={email[:3]}***")
                    await client.login(email, password, mfa_secret_key=mfa_secret, save_session=False)
                else:
                    logger.debug(f"🔍 Calling client.login without MFA, email={email[:3]}***")
                    await client.login(email, password, save_session=False)

                logger.debug(f"🔍 Login completed, token={'present' if client.token else 'missing'}")

                if client.token:
                    self.save_token(client.token)
                    logger.info("✅ Re-authentication successful, new token saved")

                return client
            except Exception as e:
                last_error = e
                error_str = str(e)
                logger.warning(f"⚠️  Auth attempt {attempt + 1} failed: {type(e).__name__}: {e}")

                if any(x in error_str for x in ["525", "SSL", "timeout", "connection", "5"]):
                    logger.debug("🔍 Transient error detected, will retry...")
                    continue
                else:
                    logger.error("❌ Non-transient error, stopping retries")
                    break

        logger.error(f"❌ Re-authentication failed after {max_retries} attempts: {type(last_error).__name__}: {last_error}")
        logger.debug(f"🔍 Traceback: {traceback.format_exc()}")
        return None

    def _cleanup_old_session_files(self) -> None:
        """Clean up old insecure session files."""
        cleanup_paths = [
            ".mm/mm_session.pickle",
            "monarch_session.json",
            ".mm",
        ]
        for path in cleanup_paths:
            try:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        os.remove(path)
                        logger.info(f"🗑️ Cleaned up old session file: {path}")
                    elif os.path.isdir(path) and not os.listdir(path):
                        os.rmdir(path)
                        logger.info(f"🗑️ Cleaned up empty session directory: {path}")
            except Exception as e:
                logger.warning(f"⚠️  Could not clean up {path}: {e}")


# Global session manager instance
secure_session = SecureMonarchSession()
