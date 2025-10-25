"""
JWT token validation service for Entra ID (Azure AD) tokens.
Implements singleton pattern using class-level instance management.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx
from jose import JWTError, jwk, jwt
from jose.utils import base64url_decode

from src.config import get_settings

logger = logging.getLogger(__name__)


class JWTValidator:
    """
    Singleton JWT validator for Entra ID tokens.
    
    Handles fetching JWKS (JSON Web Key Set), caching signing keys,
    and validating JWT tokens according to OpenID Connect standards.
    """

    _instance: Optional["JWTValidator"] = None
    _initialized: bool = False

    def __new__(cls) -> "JWTValidator":
        """Ensure only one instance of JWTValidator exists (singleton pattern)."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the JWT validator (only runs once due to singleton)."""
        if not self._initialized:
            self.settings = get_settings()
            self._jwks_cache: Dict[str, Any] = {}
            self._jwks_cache_time: Optional[datetime] = None
            self._openid_config: Optional[Dict[str, Any]] = None
            self._http_client: Optional[httpx.AsyncClient] = None
            JWTValidator._initialized = True
            logger.info("JWTValidator singleton instance initialized")

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client when shutting down."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
            logger.info("JWTValidator HTTP client closed")

    async def _fetch_openid_config(self) -> Dict[str, Any]:
        """
        Fetch OpenID Connect configuration document.
        
        Returns:
            Dict containing OpenID configuration metadata
        """
        if self._openid_config is not None:
            return self._openid_config

        try:
            logger.info(f"Fetching OpenID config from {self.settings.openid_config_url}")
            response = await self.http_client.get(self.settings.openid_config_url)
            response.raise_for_status()
            self._openid_config = response.json()
            logger.info("OpenID configuration fetched successfully")
            return self._openid_config
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch OpenID configuration: {e}")
            raise ValueError(f"Unable to fetch OpenID configuration: {e}")

    async def _fetch_jwks(self) -> Dict[str, Any]:
        """
        Fetch JSON Web Key Set (JWKS) from Entra ID.
        Implements caching with TTL to avoid excessive requests.
        
        Returns:
            Dict containing JWKS keys
        """
        # Check if cache is still valid
        if self._jwks_cache and self._jwks_cache_time:
            cache_age = datetime.utcnow() - self._jwks_cache_time
            if cache_age < timedelta(seconds=self.settings.jwks_cache_ttl):
                logger.debug("Using cached JWKS")
                return self._jwks_cache

        # Fetch new JWKS
        try:
            openid_config = await self._fetch_openid_config()
            jwks_uri = openid_config.get("jwks_uri")
            
            if not jwks_uri:
                raise ValueError("jwks_uri not found in OpenID configuration")

            logger.info(f"Fetching JWKS from {jwks_uri}")
            response = await self.http_client.get(jwks_uri)
            response.raise_for_status()
            
            self._jwks_cache = response.json()
            self._jwks_cache_time = datetime.utcnow()
            logger.info("JWKS fetched and cached successfully")
            
            return self._jwks_cache
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise ValueError(f"Unable to fetch JWKS: {e}")

    async def _get_signing_key(self, token: str) -> Dict[str, Any]:
        """
        Get the signing key for a token based on its 'kid' header.
        
        Args:
            token: The JWT token string
            
        Returns:
            Dict containing the signing key
        """
        try:
            # Decode header without verification to get 'kid'
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                raise ValueError("Token header missing 'kid' (key ID)")

            # Fetch JWKS
            jwks = await self._fetch_jwks()
            keys = jwks.get("keys", [])

            # Find the matching key
            for key in keys:
                if key.get("kid") == kid:
                    logger.debug(f"Found matching signing key for kid: {kid}")
                    return key

            raise ValueError(f"Unable to find signing key with kid: {kid}")
        
        except JWTError as e:
            logger.error(f"Error decoding token header: {e}")
            raise ValueError(f"Invalid token format: {e}")

    async def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token from Entra ID.
        
        Performs comprehensive validation:
        - Signature verification using JWKS
        - Issuer validation
        - Audience validation
        - Expiration validation
        - Not-before validation
        
        Args:
            token: The JWT token string (Bearer token without 'Bearer ' prefix)
            
        Returns:
            Dict containing the validated token claims
            
        Raises:
            ValueError: If token validation fails
        """
        try:
            # Get signing key
            signing_key = await self._get_signing_key(token)
            
            # Ensure the key has an algorithm field (Azure AD uses RS256)
            if "alg" not in signing_key:
                signing_key["alg"] = "RS256"
            
            # Convert JWK to PEM
            try:
                public_key = jwk.construct(signing_key).to_pem()
            except Exception as e:
                logger.error(f"Failed to construct public key from JWK: {e}")
                logger.debug(f"JWK data: {signing_key}")
                raise ValueError(f"Unable to construct public key: {e}")

            # Decode and validate token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.settings.expected_audience,
                issuer=self.settings.expected_issuer,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                },
            )

            # Additional custom validations
            self._validate_claims(payload)

            logger.info(f"Token validated successfully for user: {payload.get('sub', 'unknown')}")
            return payload

        except JWTError as e:
            logger.warning(f"JWT validation failed: {e}")
            raise ValueError(f"Token validation failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}")
            raise ValueError(f"Token validation error: {str(e)}")

    def _validate_claims(self, payload: Dict[str, Any]) -> None:
        """
        Perform additional custom claims validation.
        
        Args:
            payload: Decoded token payload
            
        Raises:
            ValueError: If custom validation fails
        """
        # Validate token version
        token_ver = payload.get("ver")
        # Normalize version format: both "v1.0" and "1.0" should match
        expected_ver = self.settings.token_version.replace("v", "")
        
        if token_ver and token_ver != expected_ver:
            raise ValueError(
                f"Token version mismatch. Expected {expected_ver}, got {token_ver}"
            )

        # Validate tenant ID
        tid = payload.get("tid")
        if tid and tid != self.settings.tenant_id:
            # Only validate if tenant_id is a GUID, not a domain name
            if "-" in self.settings.tenant_id and tid != self.settings.tenant_id:
                raise ValueError(
                    f"Token tenant ID mismatch. Expected {self.settings.tenant_id}, got {tid}"
                )

        logger.debug("Custom claims validation passed")


# Singleton instance getter
_validator_instance: Optional[JWTValidator] = None


def get_jwt_validator() -> JWTValidator:
    """
    Get the singleton JWT validator instance.
    
    Returns:
        JWTValidator: The singleton validator instance
    """
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = JWTValidator()
    return _validator_instance
