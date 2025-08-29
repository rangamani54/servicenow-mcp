"""
Authentication manager for the ServiceNow MCP server.
"""

import base64
import logging
import time
from typing import Dict, Optional

import requests

from servicenow_mcp.utils.config import AuthConfig, AuthType

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Authentication manager for ServiceNow API.

    This class handles authentication with the ServiceNow API using
    Basic, API key, or OAuth authentication.
    """

    def __init__(self, config: AuthConfig):
        """
        Initialize the authentication manager.

        Args:
            config: Authentication configuration.
        """
        self.config = config
        self.token: Optional[str] = None
        self.token_type: str = "Bearer"
        self.refresh_token: Optional[str] = None
        self.expires_at: float = 0  # epoch timestamp

    def get_headers(self) -> Dict[str, str]:
        """
        Get the authentication headers for API requests.

        Returns:
            Dict[str, str]: Headers to include in API requests.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self.config.type == AuthType.BASIC:
            if not self.config.basic:
                raise ValueError("Basic auth configuration is required")

            auth_str = f"{self.config.basic.username}:{self.config.basic.password}"
            encoded = base64.b64encode(auth_str.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        elif self.config.type == AuthType.OAUTH:
            if not self.token or time.time() >= self.expires_at:
                self._get_oauth_token()
            headers["Authorization"] = f"{self.token_type} {self.token}"

        elif self.config.type == AuthType.API_KEY:
            if not self.config.api_key:
                raise ValueError("API key configuration is required")
            headers[self.config.api_key.header_name] = self.config.api_key.api_key

        return headers

    def _get_oauth_token(self):
        """
        Get or refresh an OAuth token from ServiceNow.

        Raises:
            ValueError: If OAuth configuration is missing or token request fails.
        """
        if not self.config.oauth:
            raise ValueError("OAuth configuration is required")

        oauth_config = self.config.oauth
        token_url = oauth_config.token_url
        if not token_url:
            # Build default token URL from instance_url
            instance_parts = oauth_config.instance_url.split(".")
            if len(instance_parts) < 2:
                raise ValueError(f"Invalid instance URL: {oauth_config.instance_url}")
            instance_name = instance_parts[0].split("//")[-1]
            token_url = f"https://{instance_name}.service-now.com/oauth_token.do"

        # Prefer refresh token if available
        if self.refresh_token:
            data = {
                "grant_type": "refresh_token",
                "client_id": oauth_config.client_id,
                "client_secret": oauth_config.client_secret,
                "refresh_token": self.refresh_token,
            }
        else:
            data = {
                "grant_type": "password",
                "client_id": oauth_config.client_id,
                "client_secret": oauth_config.client_secret,
                "username": oauth_config.username,
                "password": oauth_config.password,
            }

        try:
            response = requests.post(token_url, data=data, timeout=30)
            response.raise_for_status()
            token_data = response.json()

            self.token = token_data.get("access_token")
            self.refresh_token = token_data.get("refresh_token", self.refresh_token)
            self.token_type = token_data.get("token_type", "Bearer")

            expires_in = token_data.get("expires_in", 1799)  # default 30 min
            self.expires_at = time.time() + expires_in - 30  # refresh early

            if not self.token:
                raise ValueError("No access token in response")

            logger.info("Successfully obtained OAuth token")

        except requests.RequestException as e:
            logger.error(f"Failed to get OAuth token: {e}")
            raise ValueError(f"Failed to get OAuth token: {e}")

    def refresh_token_if_needed(self):
        """Force refresh if using OAuth authentication."""
        if self.config.type == AuthType.OAUTH:
            if not self.token or time.time() >= self.expires_at:
                self._get_oauth_token()
