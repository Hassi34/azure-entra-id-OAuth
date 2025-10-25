"""
Token acquisition utilities for testing purposes using Device Code Flow.
This module provides helper functions to obtain JWT tokens from Entra ID.
"""

import logging
from typing import Dict, List, Optional

import httpx

from src.config import get_settings

logger = logging.getLogger(__name__)


class TokenAcquisitionError(Exception):
    """Raised when token acquisition fails."""
    pass


async def get_device_code(scopes: Optional[List[str]] = None) -> Dict[str, str]:
    """
    Initiate device code flow to get a token.
    
    Device Code Flow is the industry-standard method for:
    - CLI tools (Azure CLI, GitHub CLI, kubectl)
    - Testing APIs
    - Devices without browsers
    
    Args:
        scopes: List of scopes to request. If not provided, uses API_SCOPES from environment
        
    Returns:
        Dict containing device code information:
        {
            "device_code": "...",
            "user_code": "...",
            "verification_uri": "https://microsoft.com/devicelogin",
            "expires_in": 900,
            "interval": 5,
            "message": "To sign in, use a web browser..."
        }
    """
    settings = get_settings()
    
    if scopes is None:
        # Get scopes from environment variable (required)
        scopes = settings.scopes_list
    
    tenant_id = settings.tenant_id
    client_id = settings.client_id
    
    device_code_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    
    data = {
        "client_id": client_id,
        "scope": " ".join(scopes),
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(device_code_url, data=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.error(f"Failed to get device code: {e}")
        raise TokenAcquisitionError(f"Failed to get device code: {e}")


async def poll_for_token(device_code: str, interval: int = 5) -> Dict[str, str]:
    """
    Poll for token after user completes device code flow.
    
    Args:
        device_code: The device code from get_device_code()
        interval: Polling interval in seconds (default: 5)
        
    Returns:
        Dict containing token information:
        {
            "access_token": "eyJ0eXAiOiJKV1Qi...",
            "token_type": "Bearer",
            "expires_in": 3599,
            "scope": "...",
            "refresh_token": "..."
        }
        
    Raises:
        TokenAcquisitionError: If authentication fails or is still pending
    """
    settings = get_settings()
    
    tenant_id = settings.tenant_id
    client_id = settings.client_id
    
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": device_code,
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            
            # Log the response for debugging
            logger.info(f"Token response status: {response.status_code}")
            
            if response.status_code in [400, 401]:
                try:
                    error_data = response.json()
                    error = error_data.get("error", "unknown_error")
                    error_description = error_data.get("error_description", "")
                    
                    logger.error(f"Token error: {error} - {error_description}")
                    
                    if error == "authorization_pending":
                        raise TokenAcquisitionError("User has not yet completed authentication")
                    elif error == "authorization_declined":
                        raise TokenAcquisitionError("User declined the authentication request")
                    elif error == "expired_token":
                        raise TokenAcquisitionError("Device code has expired. Please request a new device code.")
                    elif error == "bad_verification_code":
                        raise TokenAcquisitionError("Invalid device code. Please request a new device code.")
                    else:
                        raise TokenAcquisitionError(f"Token acquisition failed: {error} - {error_description}")
                except Exception as json_error:
                    # If we can't parse JSON, raise the raw error
                    raise TokenAcquisitionError(f"Token request failed with status {response.status_code}: {response.text}")
            
            response.raise_for_status()
            return response.json()
            
    except TokenAcquisitionError:
        # Re-raise our custom errors
        raise
    except httpx.HTTPError as e:
        logger.error(f"Failed to get token: {e}")
        raise TokenAcquisitionError(f"Failed to get token: {e}")
