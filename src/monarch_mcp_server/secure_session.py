"""
Secure session management for Monarch Money MCP Server using keyring.
"""

import asyncio
import keyring
import logging
import os
import traceback
from typing import Optional, Tuple
from monarchmoney import MonarchMoney

logger = logging.getLogger(__name__)

# PATCH: Monarch Money changed their API endpoint (see https://github.com/hammem/monarchmoney/issues/179)
# Note: BASE_URL is on MonarchMoneyEndpoints class, not MonarchMoney
from monarchmoney.monarchmoney import MonarchMoneyEndpoints
MonarchMoneyEndpoints.BASE_URL = "https://api.monarch.com"

# Add file handler to match server.py debug logging
_debug_file_handler = logging.FileHandler("/tmp/monarch-mcp-debug.log")
_debug_file_handler.setLevel(logging.DEBUG)
_debug_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(_debug_file_handler)
logger.setLevel(logging.DEBUG)

# Keyring service identifiers
KEYRING_SERVICE = "com.mcp.monarch-mcp-server"
KEYRING_USERNAME = "monarch-token"
KEYRING_EMAIL = "monarch-email"
KEYRING_PASSWORD = "monarch-password"
KEYRING_MFA_SECRET = "monarch-mfa-secret"


class SecureMonarchSession:
    """Manages Monarch Money sessions securely using the system keyring."""

    def save_credentials(self, email: str, password: str, mfa_secret: Optional[str] = None) -> None:
        """Save email, password, and optionally MFA secret to keyring for auto-re-authentication."""
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_EMAIL, email)
            keyring.set_password(KEYRING_SERVICE, KEYRING_PASSWORD, password)
            if mfa_secret:
                keyring.set_password(KEYRING_SERVICE, KEYRING_MFA_SECRET, mfa_secret)
                logger.info("✅ Credentials + MFA secret saved securely to keyring")
            else:
                logger.info("✅ Credentials saved securely to keyring")
        except Exception as e:
            logger.error(f"❌ Failed to save credentials to keyring: {e}")
            raise

    def save_mfa_secret(self, mfa_secret: str) -> None:
        """Save MFA secret key to keyring."""
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_MFA_SECRET, mfa_secret)
            logger.info("✅ MFA secret saved securely to keyring")
        except Exception as e:
            logger.error(f"❌ Failed to save MFA secret to keyring: {e}")
            raise

    def load_credentials(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Load email, password, and MFA secret from keyring."""
        try:
            logger.debug("🔍 Attempting to load credentials from keyring...")
            email = keyring.get_password(KEYRING_SERVICE, KEYRING_EMAIL)
            password = keyring.get_password(KEYRING_SERVICE, KEYRING_PASSWORD)
            mfa_secret = keyring.get_password(KEYRING_SERVICE, KEYRING_MFA_SECRET)
            logger.debug(f"🔍 Credentials loaded: email={'yes' if email else 'no'}, password={'yes' if password else 'no'}, mfa={'yes' if mfa_secret else 'no'}")
            if email and password:
                logger.info("✅ Credentials loaded from keyring")
            return email, password, mfa_secret
        except Exception as e:
            logger.error(f"❌ Failed to load credentials from keyring: {e}")
            return None, None, None

    def delete_credentials(self) -> None:
        """Delete stored credentials from keyring."""
        for key in [KEYRING_EMAIL, KEYRING_PASSWORD, KEYRING_MFA_SECRET]:
            try:
                keyring.delete_password(KEYRING_SERVICE, key)
            except keyring.errors.PasswordDeleteError:
                pass
            except Exception as e:
                logger.warning(f"⚠️  Could not delete {key}: {e}")
        logger.info("🗑️ Credentials deleted from keyring")

    def save_token(self, token: str) -> None:
        """Save the authentication token to the system keyring."""
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, token)
            logger.info("✅ Token saved securely to keyring")

            # Clean up any old insecure files
            self._cleanup_old_session_files()

        except Exception as e:
            logger.error(f"❌ Failed to save token to keyring: {e}")
            raise

    def load_token(self) -> Optional[str]:
        """Load the authentication token from the system keyring."""
        try:
            logger.debug(f"🔍 load_token() - Attempting keyring.get_password({KEYRING_SERVICE}, {KEYRING_USERNAME})")
            token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if token:
                logger.info(f"✅ Token loaded from keyring (length: {len(token)})")
                return token
            else:
                logger.info("🔍 No token found in keyring")
                return None
        except Exception as e:
            logger.error(f"❌ Failed to load token from keyring: {type(e).__name__}: {e}")
            return None

    def delete_token(self) -> None:
        """Delete the authentication token from the system keyring."""
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
            logger.info("🗑️ Token deleted from keyring")

            # Also clean up any old insecure files
            self._cleanup_old_session_files()

        except keyring.errors.PasswordDeleteError:
            logger.info("🔍 No token found in keyring to delete")
        except Exception as e:
            logger.error(f"❌ Failed to delete token from keyring: {e}")

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
                    wait_time = 2 ** attempt  # Exponential backoff: 2, 4, 8 seconds
                    logger.info(f"🔄 Retry {attempt + 1}/{max_retries} after {wait_time}s...")
                    await asyncio.sleep(wait_time)

                logger.info("🔄 Attempting re-authentication with stored credentials...")
                client = MonarchMoney()

                # Use MFA secret key if available for seamless re-auth
                # IMPORTANT: save_session=False prevents monarchmoney from trying to create
                # a .mm/ directory, which fails when running from Claude Desktop (runs from /)
                if mfa_secret:
                    logger.info("🔐 Using stored MFA secret for authentication")
                    logger.debug(f"🔍 Calling client.login with email={email[:3]}***")
                    await client.login(email, password, mfa_secret_key=mfa_secret, save_session=False)
                else:
                    logger.debug(f"🔍 Calling client.login without MFA, email={email[:3]}***")
                    await client.login(email, password, save_session=False)

                logger.debug(f"🔍 Login completed, token={'present' if client.token else 'missing'}")

                # Save the new token
                if client.token:
                    self.save_token(client.token)
                    logger.info("✅ Re-authentication successful, new token saved")

                return client
            except Exception as e:
                last_error = e
                error_str = str(e)
                logger.warning(f"⚠️  Auth attempt {attempt + 1} failed: {type(e).__name__}: {e}")

                # Retry on transient errors (SSL, network, 5xx)
                if any(x in error_str for x in ["525", "SSL", "timeout", "connection", "5"]):
                    logger.debug("🔍 Transient error detected, will retry...")
                    continue
                else:
                    # Non-transient error, don't retry
                    logger.error(f"❌ Non-transient error, stopping retries")
                    break

        logger.error(f"❌ Re-authentication failed after {max_retries} attempts: {type(last_error).__name__}: {last_error}")
        logger.debug(f"🔍 Traceback: {traceback.format_exc()}")
        return None

    def _cleanup_old_session_files(self) -> None:
        """Clean up old insecure session files."""
        cleanup_paths = [
            ".mm/mm_session.pickle",
            "monarch_session.json",
            ".mm",  # Remove the entire directory if empty
        ]

        for path in cleanup_paths:
            try:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        os.remove(path)
                        logger.info(f"🗑️ Cleaned up old insecure session file: {path}")
                    elif os.path.isdir(path) and not os.listdir(path):
                        os.rmdir(path)
                        logger.info(f"🗑️ Cleaned up empty session directory: {path}")
            except Exception as e:
                logger.warning(f"⚠️  Could not clean up {path}: {e}")


# Global session manager instance
secure_session = SecureMonarchSession()
