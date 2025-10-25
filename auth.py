######## auth ###############
#__init__.py

"""Authentication package initialization."""

from .dependencies import (
    get_current_user,
    get_token_payload,
    require_any_role,
    require_role,
)
from .jwt_validator import JWTValidator, get_jwt_validator

__all__ = [
    "JWTValidator",
    "get_jwt_validator",
    "get_token_payload",
    "get_current_user",
    "require_role",
    "require_any_role",
]

# dependencies.py

"""
Authentication dependencies and models for FastAPI.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.auth.jwt_validator import get_jwt_validator
from src.config import get_settings
from src.models.user import AuthenticatedUser

logger = logging.getLogger(__name__)

# HTTP Bearer token extractor
security = HTTPBearer(
    scheme_name="Bearer",
    description="JWT token from Entra ID (Azure AD)",
    auto_error=False,
)


async def get_token_payload(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """
    Dependency to extract and validate JWT token from Authorization header.
    
    Args:
        credentials: HTTP Authorization credentials (Bearer token)
        
    Returns:
        Dict containing validated token claims
        
    Raises:
        HTTPException: If token is missing or invalid
    """
    if not credentials:
        logger.warning("No authorization credentials provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    
    try:
        validator = get_jwt_validator()
        payload = await validator.validate_token(token)
        return payload
    
    except ValueError as e:
        logger.warning(f"Token validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error",
        )


async def get_current_user(
    payload: Dict[str, Any] = Depends(get_token_payload),
) -> AuthenticatedUser:
    """
    Dependency to extract authenticated user information from token payload.
    
    Args:
        payload: Validated JWT token payload
        
    Returns:
        AuthenticatedUser: Structured user information
    """
    try:
        user = AuthenticatedUser.from_token_payload(payload)
        logger.info(f"User authenticated: {user.email or user.subject}")
        return user
    
    except Exception as e:
        logger.error(f"Error creating user from token payload: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload structure",
        )


def require_role(required_role: str):
    """
    Dependency factory to require specific app role.
    
    Args:
        required_role: The role that must be present (e.g., "Admin", "PowerUser", "ReadOnly")
        
    Returns:
        Dependency function that validates the role
        
    Usage:
        @app.delete("/api/data/{id}")
        async def delete_data(
            id: str,
            _: None = Depends(require_role("Admin"))
        ):
            return {"status": "deleted"}
    """
    async def role_checker(user: AuthenticatedUser = Depends(get_current_user)) -> None:
        """Check if required role is present."""
        if not user.has_role(required_role):
            logger.warning(
                f"Required role '{required_role}' not found. "
                f"User: {user.email}, Roles: {user.roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role '{required_role}' not present. User has: {user.roles}",
            )
    
    return role_checker


def require_any_role(*required_roles: str):
    """
    Dependency factory to require at least one of the specified roles.
    
    Args:
        required_roles: Roles, at least one of which must be present
        
    Returns:
        Dependency function that validates roles
        
    Usage:
        @app.post("/api/data")
        async def create_data(
            data: dict,
            _: None = Depends(require_any_role("Admin", "PowerUser"))
        ):
            return {"status": "created"}
    """
    async def role_checker(user: AuthenticatedUser = Depends(get_current_user)) -> None:
        """Check if at least one required role is present."""
        if not user.has_any_role(*required_roles):
            logger.warning(
                f"None of the required roles {required_roles} found. "
                f"User: {user.email}, Roles: {user.roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required one of roles: {required_roles}. User has: {user.roles}",
            )
    
    return role_checker

# jwt_validator.py

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

# token_helper.py

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

################### config ################
#__init__.py
"""Configuration package initialization."""

from .settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]

# settings.py
"""
Configuration management for the application using Pydantic Settings.
Implements singleton pattern to ensure single instance throughout the application.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Uses Pydantic Settings for validation and type safety.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application settings
    app_name: str = Field(default="EntraID JWT Auth API", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    
    # Server settings
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    
    # Entra ID / Azure AD settings
    tenant_id: str = Field(
        ...,
        description="Azure AD Tenant ID (GUID or domain name like contoso.onmicrosoft.com)",
    )
    client_id: str = Field(
        ...,
        description="Application (client) ID from Azure App Registration",
    )
    
    # Optional: For validating specific audiences
    audience: Optional[str] = Field(
        default=None,
        description="Expected audience (aud claim) in JWT token. If not set, defaults to client_id",
    )
    
    # Token validation settings
    token_version: str = Field(
        default="v2.0",
        description="Azure AD token version (v1.0 or v2.0)",
    )
    
    # Authority and OpenID endpoints
    authority: Optional[str] = Field(
        default=None,
        description="Authority URL. If not provided, will be constructed from tenant_id",
    )
    
    # JWKS cache settings
    jwks_cache_ttl: int = Field(
        default=86400,  # 24 hours
        description="Time to live for JWKS cache in seconds",
    )
    
    # CORS settings
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000",
        description="Comma-separated list of allowed CORS origins",
    )
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
    
    # API scopes for token acquisition
    api_scopes: str = Field(
        ...,
        description="Space-separated API scope names (e.g., 'api.scope demo_oauth')",
    )
    
    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant ID is not empty."""
        if not v or v.strip() == "":
            raise ValueError("tenant_id must be provided")
        return v.strip()
    
    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        """Validate client ID is not empty."""
        if not v or v.strip() == "":
            raise ValueError("client_id must be provided")
        return v.strip()
    
    @field_validator("api_scopes")
    @classmethod
    def validate_api_scopes(cls, v: str) -> str:
        """Validate API scopes is not empty."""
        if not v or v.strip() == "":
            raise ValueError("api_scopes must be provided in environment variables")
        return v.strip()
    
    @property
    def oidc_authority(self) -> str:
        """Get the OpenID Connect authority URL."""
        if self.authority:
            return self.authority
        # v1.0 tokens don't use version in the authority URL
        if self.token_version == "v1.0":
            return f"https://login.microsoftonline.com/{self.tenant_id}"
        return f"https://login.microsoftonline.com/{self.tenant_id}/{self.token_version}"
    
    @property
    def openid_config_url(self) -> str:
        """Get the OpenID configuration document URL."""
        return f"{self.oidc_authority}/.well-known/openid-configuration"
    
    @property
    def expected_audience(self) -> str:
        """
        Get the expected audience for token validation.
        If audience is not explicitly set, constructs it from client_id with api:// prefix.
        """
        if self.audience:
            return self.audience
        # Default to api://client_id format (standard for Azure AD app registrations)
        return f"api://{self.client_id}"
    
    @property
    def expected_issuer(self) -> str:
        """
        Get the expected issuer for token validation.
        For v1.0 tokens: https://sts.windows.net/{tenant_id}/
        For v2.0 tokens: https://login.microsoftonline.com/{tenant_id}/v2.0
        """
        if self.token_version == "v1.0":
            return f"https://sts.windows.net/{self.tenant_id}/"
        return f"https://login.microsoftonline.com/{self.tenant_id}/{self.token_version}"
    
    @property
    def scopes_list(self) -> List[str]:
        """
        Get API scopes as a list with full URIs.
        Automatically constructs api://{client_id}/{scope} format.
        """
        return [f"api://{self.client_id}/{scope.strip()}" 
                for scope in self.api_scopes.split() if scope.strip()]


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings instance (singleton pattern using lru_cache).
    
    This ensures only one Settings instance is created and reused throughout
    the application lifecycle, providing efficient configuration access.
    
    Returns:
        Settings: The application settings instance
    """
    return Settings()

######################### models ####################
# __init__.py
"""Models package initialization."""

from .user import AuthenticatedUser

__all__ = ["AuthenticatedUser"]
# user.py

"""
User models for authenticated users.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuthenticatedUser(BaseModel):
    """
    Represents an authenticated user from Entra ID token.
    """

    subject: str = Field(..., description="Unique user identifier (sub claim)")
    name: Optional[str] = Field(None, description="User's display name")
    email: Optional[str] = Field(None, description="User's email address (if available)")
    preferred_username: Optional[str] = Field(None, description="Preferred username")
    
    tenant_id: Optional[str] = Field(None, description="Azure AD tenant ID")
    object_id: Optional[str] = Field(None, description="User's object ID in Azure AD")
    
    scopes: List[str] = Field(default_factory=list, description="Token scopes")
    roles: List[str] = Field(default_factory=list, description="User roles")
    
    issued_at: Optional[datetime] = Field(None, description="Token issued at time")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")
    
    app_id: Optional[str] = Field(None, description="Application ID that requested the token")
    
    @classmethod
    def from_token_payload(cls, payload: Dict[str, Any]) -> "AuthenticatedUser":
        """
        Create AuthenticatedUser from JWT token payload.
        
        Args:
            payload: Decoded JWT token payload
            
        Returns:
            AuthenticatedUser instance
        """
        # Parse scopes (can be in 'scp' claim as space-separated string)
        scopes = []
        if "scp" in payload:
            scopes = payload["scp"].split() if isinstance(payload["scp"], str) else payload["scp"]
        elif "scope" in payload:
            scopes = payload["scope"].split() if isinstance(payload["scope"], str) else payload["scope"]
        
        # Parse roles
        roles = payload.get("roles", [])
        
        # Parse timestamps
        issued_at = None
        if "iat" in payload:
            issued_at = datetime.fromtimestamp(payload["iat"])
        
        expires_at = None
        if "exp" in payload:
            expires_at = datetime.fromtimestamp(payload["exp"])
        
        # Extract email from various possible claims
        # v1.0 tokens: upn, unique_name
        # v2.0 tokens: email, preferred_username
        email = (
            payload.get("email") or 
            payload.get("upn") or 
            payload.get("unique_name") or 
            payload.get("preferred_username")
        )
        
        return cls(
            subject=payload.get("sub", payload.get("oid", "unknown")),
            name=payload.get("name"),
            email=email,
            preferred_username=payload.get("preferred_username") or payload.get("upn"),
            tenant_id=payload.get("tid"),
            object_id=payload.get("oid"),
            scopes=scopes,
            roles=roles,
            issued_at=issued_at,
            expires_at=expires_at,
            app_id=payload.get("appid") or payload.get("azp"),
        )
    
    def has_scope(self, scope: str) -> bool:
        """
        Check if user has a specific scope.
        
        Args:
            scope: Scope to check
            
        Returns:
            bool: True if user has the scope
        """
        return scope in self.scopes
    
    def has_any_scope(self, *scopes: str) -> bool:
        """
        Check if user has at least one of the specified scopes.
        
        Args:
            scopes: Scopes to check
            
        Returns:
            bool: True if user has at least one scope
        """
        for scope in scopes:
            if self.has_scope(scope):
                return True
        return False
    
    def has_all_scopes(self, *scopes: str) -> bool:
        """
        Check if user has all specified scopes.
        
        Args:
            scopes: Scopes to check
            
        Returns:
            bool: True if user has all scopes
        """
        for scope in scopes:
            if not self.has_scope(scope):
                return False
        return True
    
    def has_role(self, role: str) -> bool:
        """
        Check if user has a specific role.
        
        Args:
            role: Role to check (e.g., "Admin", "PowerUser", "ReadOnly")
            
        Returns:
            bool: True if user has the role
        """
        return role in self.roles
    
    def has_any_role(self, *roles: str) -> bool:
        """
        Check if user has at least one of the specified roles.
        
        Args:
            roles: Roles to check
            
        Returns:
            bool: True if user has at least one role
        """
        return any(role in self.roles for role in roles)
    
    @property
    def is_admin(self) -> bool:
        """Check if user has AdminUser role."""
        return self.has_role("AppRole.AdminUser")
    
    @property
    def can_write(self) -> bool:
        """Check if user can write data (BasicUser or AdminUser)."""
        return self.has_any_role("AppRole.AdminUser", "AppRole.BasicUser")
    
    @property
    def can_read(self) -> bool:
        """Check if user can read data (BasicUser or AdminUser)."""
        return self.has_any_role("AppRole.BasicUser", "AppRole.AdminUser")

############## src #######################
#__init__.py
"""Source package initialization."""

__version__ = "1.0.0"
# main.py
"""
Main FastAPI application with Entra ID JWT authentication.
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.auth import get_current_user, get_jwt_validator, require_role
from src.auth.token_helper import (
    TokenAcquisitionError,
    get_device_code,
    poll_for_token,
)
from src.config import get_settings
from src.models import AuthenticatedUser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown events.
    """
    # Startup
    logger.info("Starting up application...")
    logger.info(f"Tenant ID: {settings.tenant_id}")
    logger.info(f"Client ID: {settings.client_id}")
    logger.info(f"Authority: {settings.oidc_authority}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    validator = get_jwt_validator()
    await validator.close()
    logger.info("Application shutdown complete")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="FastAPI application with Entra ID (Azure AD) JWT authentication",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Health"])
async def root():
    """
    Root endpoint - public access.
    """
    return {
        "message": "Welcome to Entra ID JWT Authentication API",
        "version": settings.app_version,
        "status": "operational",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint - public access.
    """
    return {
        "status": "healthy",
        "timestamp": "2025-10-22T00:00:00Z",
    }


@app.get("/api/protected", tags=["Protected"])
async def protected_endpoint(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(require_role("AppRole.BasicUser")),
):
    """
    Protected endpoint - requires valid JWT token and AppRole.BasicUser role.
    
    This is a sample protected endpoint that demonstrates JWT authentication with role-based access.
    """
    return {
        "message": "Access granted to protected resource",
        "user": {
            "subject": current_user.subject,
            "name": current_user.name,
            "email": current_user.email,
            "tenant_id": current_user.tenant_id,
            "scopes": current_user.scopes,
            "roles": current_user.roles,
        },
    }


@app.get("/api/user/profile", tags=["User"])
async def get_user_profile(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(require_role("AppRole.BasicUser")),
):
    """
    Get authenticated user's profile information.
    
    Requires: AppRole.BasicUser role
    
    Returns detailed information about the currently authenticated user
    extracted from the JWT token claims.
    """
    return {
        "profile": {
            "subject": current_user.subject,
            "name": current_user.name,
            "email": current_user.email,
            "preferred_username": current_user.preferred_username,
            "tenant_id": current_user.tenant_id,
            "object_id": current_user.object_id,
            "scopes": current_user.scopes,
            "roles": current_user.roles,
            "app_id": current_user.app_id,
        },
        "token_info": {
            "issued_at": current_user.issued_at.isoformat() if current_user.issued_at else None,
            "expires_at": current_user.expires_at.isoformat() if current_user.expires_at else None,
        },
    }


@app.get("/api/user/permissions", tags=["User"])
async def get_user_permissions(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(require_role("AppRole.AdminUser")),
):
    """
    Get authenticated user's permissions (scopes and roles).
    
    Requires: AppRole.AdminUser role (Admin only)
    """
    return {
        "permissions": {
            "scopes": current_user.scopes,
            "roles": current_user.roles,
            "all_permissions": list(set(current_user.scopes + current_user.roles)),
        }
    }


@app.get("/auth/device-code", tags=["Authentication"])
async def get_device_code_endpoint():
    """
    Initiate device code flow for authentication.
    
    This is useful for testing and for devices without a browser.
    
    Returns device code information that user needs to complete authentication.
    """
    try:
        device_code_response = await get_device_code()
        
        return {
            "message": "Device code flow initiated",
            "user_code": device_code_response.get("user_code"),
            "device_code": device_code_response.get("device_code"),
            "verification_uri": device_code_response.get("verification_uri"),
            "expires_in": device_code_response.get("expires_in"),
            "interval": device_code_response.get("interval"),
            "instructions": [
                f"1. Visit: {device_code_response.get('verification_uri')}",
                f"2. Enter code: {device_code_response.get('user_code')}",
                "3. Sign in with your Microsoft account",
                "4. Poll /auth/device-token endpoint with the device_code"
            ],
            "next_step": {
                "endpoint": "/auth/device-token",
                "method": "POST",
                "body": {
                    "device_code": device_code_response.get("device_code")
                }
            }
        }
    except TokenAcquisitionError as e:
        logger.error(f"Failed to get device code: {e}")
        return JSONResponse(
            status_code=400,
            content={"error": "Failed to initiate device code flow", "detail": str(e)}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Device code flow failed", "detail": str(e)}
        )


@app.post("/auth/device-token", tags=["Authentication"])
async def get_device_token_endpoint(device_code: str):
    """
    Poll for access token after user completes device code authentication.
    
    Body Parameters:
        device_code: The device code from /auth/device-code endpoint
    
    Note: You may need to poll this endpoint multiple times until user completes authentication.
    """
    try:
        token_response = await poll_for_token(device_code)
        
        return {
            "message": "Successfully obtained access token",
            "access_token": token_response.get("access_token"),
            "token_type": token_response.get("token_type", "Bearer"),
            "expires_in": token_response.get("expires_in"),
            "scope": token_response.get("scope"),
            "refresh_token": token_response.get("refresh_token"),
            "usage": {
                "instructions": "Use the access_token in Authorization header",
                "example": f"Authorization: Bearer {token_response.get('access_token', '...')[:50]}..."
            }
        }
    except TokenAcquisitionError as e:
        error_message = str(e)
        status_code = 400
        
        if "authorization_pending" in error_message.lower():
            status_code = 202  # Accepted - try again
            error_message = "User has not completed authentication yet. Please try again."
        elif "expired" in error_message.lower():
            status_code = 400
        
        return JSONResponse(
            status_code=status_code,
            content={"error": "Token not ready", "detail": error_message}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Token acquisition failed", "detail": str(e)}
        )


# Role-Based Access Control Endpoints
@app.get("/api/admin/users", tags=["Admin"])
async def list_users_admin(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(require_role("AppRole.AdminUser")),
):
    """
    Admin-only endpoint to list users.
    
    Requires: AppRole.AdminUser role
    """
    return {
        "message": "Admin access granted",
        "admin": current_user.email,
        "users": [
            {"id": 1, "name": "User 1", "email": "user1@company.com"},
            {"id": 2, "name": "User 2", "email": "user2@company.com"},
            {"id": 3, "name": "User 3", "email": "user3@company.com"},
        ]
    }


@app.get("/api/user/capabilities", tags=["User"])
async def get_user_capabilities(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(require_role("AppRole.BasicUser")),
):
    """
    Get user capabilities based on their roles.
    
    Requires: AppRole.BasicUser role
    
    Returns: What actions the current user can perform
    """
    capabilities = {
        "can_read": current_user.can_read,
        "can_write": current_user.can_write,
        "is_admin": current_user.is_admin,
        "roles": current_user.roles,
        "available_actions": []
    }
    
    if current_user.can_read:
        capabilities["available_actions"].append("read_data")
    
    if current_user.can_write:
        capabilities["available_actions"].extend(["create_data", "update_data"])
    
    if current_user.is_admin:
        capabilities["available_actions"].extend(["delete_data", "manage_users", "admin_panel"])
    
    return capabilities


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    Global exception handler for unhandled exceptions.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again later.",
        },
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info",
    )

############### root ########################
# env.example
# Environment Configuration for Entra ID JWT Authentication

# Application Settings
APP_NAME="EntraID JWT Auth API"
APP_VERSION="1.0.0"
DEBUG=False

# Server Settings
HOST=0.0.0.0
PORT=8000

# Entra ID / Azure AD Configuration
# Required: Get these from Azure Portal -> App Registrations
TENANT_ID=your-tenant-id-here
CLIENT_ID=your-client-id-here

# API Scopes for token acquisition (space-separated short names)
# Format: Short scope names without api:// prefix
# The application will automatically construct full URIs: api://{CLIENT_ID}/{scope_name}
# Example: api.scope demo_oauth
API_SCOPES=api.scope demo_oauth

# Audience validation (defaults to api://{CLIENT_ID} if not set)
AUDIENCE=api://your-client-id-here

# Token Version (v1.0 or v2.0)
TOKEN_VERSION=v1.0

# JWKS Cache Settings (in seconds)
JWKS_CACHE_TTL=86400

# CORS Settings (comma-separated origins)
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,https://yourdomain.com

# pyproject.toml
[project]
name = "entraid-jwt-auth"
version = "0.1.0"
description = "Production-ready FastAPI project with Entra ID JWT authentication"
authors = [
    {name = "Your Name", email = "your.email@example.com"}
]
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "python-jose[cryptography]>=3.3.0",
    "httpx>=0.27.0",
    "pydantic>=2.9.0",
    "pydantic-settings>=2.5.0",
    "python-multipart>=0.0.12",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "black>=24.8.0",
    "ruff>=0.7.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src"]

[tool.black]
line-length = 100
target-version = ["py311"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP"]
ignore = []

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

# .env
# Application Settings
APP_NAME="EntraID JWT Auth API"
APP_VERSION="1.0.0"
DEBUG=True

# Server Settings
HOST=0.0.0.0
PORT=8000

# Entra ID / Azure AD Configuration
# Required: Get these from Azure Portal -> App Registrations
TENANT_ID=a29f1550-7848-4264-b780-2874985f7fb0
CLIENT_ID=4546d1ba-b797-41c6-af59-c7e198b59882

API_SCOPES=api.scope demo_oauth

#Audience validation (defaults to CLIENT_ID if not set)
AUDIENCE=api://4546d1ba-b797-41c6-af59-c7e198b59882

# Token Version (v1.0 or v2.0)
TOKEN_VERSION=v1.0

# JWKS Cache Settings (in seconds)
JWKS_CACHE_TTL=86400

# CORS Settings (comma-separated origins)
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,https://yourdomain.com

# README.md
# Entra ID JWT Authentication - FastAPI

A production-ready FastAPI application with Microsoft Entra ID (formerly Azure AD) JWT token authentication. This project demonstrates best practices including singleton patterns, async/await, and comprehensive token validation.

## Features

- ✅ **JWT Token Validation** - Complete validation of Entra ID access tokens (v1.0 and v2.0)
- ✅ **JWKS Caching** - Efficient caching of JSON Web Key Sets with configurable TTL
- ✅ **Singleton Pattern** - Proper singleton implementation for validators and configuration
- ✅ **Async/Await** - Full async support for high performance
- ✅ **Type Safety** - Pydantic models for configuration and data validation
- ✅ **Production Ready** - Proper logging, error handling, and CORS support
- ✅ **Role-Based Access Control (RBAC)** - Support for Azure AD app roles
- ✅ **Scope Validation** - Validate required OAuth 2.0 scopes
- ✅ **Multiple Endpoints** - Sample protected API endpoints demonstrating usage
- ✅ **Device Code Flow** - Built-in token acquisition for testing and development

## Authentication & Authorization Flow

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant API as FastAPI API
    participant Azure as Azure AD/Entra ID
    participant JWKS as JWKS Endpoint

    Note over User,JWKS: 1. Token Acquisition (Device Code Flow)
    
    User->>API: GET /auth/device-code
    API->>Azure: Request device code
    Azure-->>API: device_code, user_code, verification_uri
    API-->>User: Display user_code & verification_uri
    
    User->>Browser: Visit verification_uri
    Browser->>Azure: Enter user_code
    User->>Azure: Sign in + MFA + Consent
    Azure-->>Browser: Authentication successful
    
    User->>API: POST /auth/device-token (device_code)
    API->>Azure: Poll for token
    Azure-->>API: access_token (JWT)
    API-->>User: Return access_token
    
    Note over User,JWKS: 2. API Request with Token
    
    User->>API: GET /api/user/profile<br/>Authorization: Bearer {token}
    
    Note over API,JWKS: 3. Token Validation
    
    API->>API: Extract token from header
    API->>API: Decode token header (get kid)
    
    alt JWKS Cache Miss
        API->>Azure: GET /.well-known/openid-configuration
        Azure-->>API: OpenID config (jwks_uri)
        API->>JWKS: GET jwks_uri
        JWKS-->>API: Public keys (JWKS)
        API->>API: Cache JWKS (24h TTL)
    else JWKS Cache Hit
        API->>API: Use cached JWKS
    end
    
    API->>API: Find signing key by kid
    API->>API: Verify JWT signature (RS256)
    API->>API: Validate claims:<br/>- aud: api://client-id<br/>- iss: sts.windows.net/tenant<br/>- exp: not expired<br/>- ver: 1.0 or 2.0
    
    Note over API: 4. Authorization (RBAC)
    
    API->>API: Extract roles from token
    API->>API: Check required role:<br/>AppRole.BasicUser ✓
    
    alt User Has Required Role
        API->>API: Extract user info:<br/>- email from upn/unique_name<br/>- name, oid, scopes
        API-->>User: 200 OK + User Profile
    else User Missing Role
        API-->>User: 403 Forbidden
    end
    
    Note over API: Token validation failures
    alt Invalid Signature
        API-->>User: 401 Unauthorized:<br/>"Signature verification failed"
    else Invalid Audience
        API-->>User: 401 Unauthorized:<br/>"Invalid audience"
    else Token Expired
        API-->>User: 401 Unauthorized:<br/>"Token expired"
    else Missing Required Role
        API-->>User: 403 Forbidden:<br/>"Insufficient permissions"
    end
```

### Flow Breakdown

1. **Token Acquisition (Device Code Flow)**
   - User requests device code from API
   - User completes authentication in browser (with MFA)
   - API polls Azure AD and receives JWT access token
   - Token contains: scopes (`scp`), roles (`roles`), user info

2. **API Request with Token**
   - User sends request with `Authorization: Bearer {token}` header
   - FastAPI security extracts token

3. **Token Validation**
   - Decode token header to get `kid` (key ID)
   - Fetch JWKS from Azure AD (cached for 24h)
   - Verify JWT signature using RS256 algorithm
   - Validate claims: audience, issuer, expiration, version

4. **Authorization (RBAC)**
   - Extract roles from token's `roles` claim
   - Check if user has required role (e.g., `AppRole.BasicUser`)
   - Extract user information from token claims
   - Return user profile or 403 Forbidden

## Project Structure

```
EntraID Authentication & Authorization/
├── src/
│   ├── __init__.py
│   ├── main.py                    # FastAPI application
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_validator.py       # JWT validation service (singleton)
│   │   └── dependencies.py        # FastAPI auth dependencies
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py            # Configuration management (singleton)
│   └── models/
│       ├── __init__.py
│       └── user.py                # User models
├── pyproject.toml                 # Project dependencies
├── env.example                    # Environment variables template
└── README.md                      # This file
```

## Prerequisites

- Python 3.11 or higher
- Azure AD tenant with an app registration
- Access token from Entra ID

## Setup Instructions

### 1. Azure AD App Registration

Complete these steps in Azure Portal to configure your application:

#### Step 1.1: Create App Registration

1. Go to [Azure Portal](https://portal.azure.com) → **Azure Active Directory** → **App registrations**
2. Click **"New registration"**
3. Configure your application:
   - **Name**: Your API name (e.g., "My API")
   - **Supported account types**: Choose based on your needs
     - Single tenant (most common for enterprise apps)
     - Multi-tenant (if your API serves multiple organizations)
   - **Redirect URI**: Leave blank (not needed for API-only apps)
4. Click **"Register"**
5. After creation, note down:
   - **Application (client) ID** - You'll need this for `CLIENT_ID`
   - **Directory (tenant) ID** - You'll need this for `TENANT_ID`

#### Step 1.2: Enable Public Client Flow (Required for Device Code Flow)

⚠️ **CRITICAL**: This step is required for the device code authentication to work!

1. In your app registration, click **"Authentication"** in the left menu
2. Scroll down to **"Advanced settings"**
3. Under **"Allow public client flows"**, find the toggle:
   - **"Enable the following mobile and desktop flows"**
4. Set it to **"Yes"**
5. Click **"Save"** at the top

**Why?** Device code flow is designed for public clients (CLIs, testing tools) that cannot securely store client secrets. Without this setting, you'll get a `401 Unauthorized` error.

#### Step 1.3: Configure API Permissions

1. Click **"API permissions"** in the left menu
2. You should see **Microsoft Graph → User.Read** (added by default)
3. If you need additional permissions:
   - Click **"+ Add a permission"**
   - Choose **Microsoft Graph** or your custom API
   - Select **Delegated permissions**
   - Search and select the required permissions
   - Click **"Add permissions"**
4. (Optional) Click **"Grant admin consent for [Your Tenant]"**
   - This pre-approves permissions for all users
   - Recommended for enterprise deployments

**Common permissions:**
- `User.Read` - Read user profile (included by default)
- `email`, `profile`, `openid` - Basic user info
- `offline_access` - Get refresh tokens

#### Step 1.4: Expose Your API (Required - For Custom API Scopes)

⚠️ **REQUIRED**: You must expose your API and create at least one scope for the authentication to work!

1. Click **"Expose an API"** in the left menu
2. Click **"+ Set"** next to "Application ID URI"
   - Default: `api://{your-client-id}` (recommended)
   - Example: `api://4546d1ba-b797-41c6-af59-c7e198b59882`
   - Or use custom URI: `https://yourdomain.com/api`
3. Click **"Save"**
4. Click **"+ Add a scope"** to create your first scope:
   - **Scope name**: `api.scope` (you can use any name like `access_as_user`, `api.read`, etc.)
   - **Who can consent**: **Admins and users** (or Admins only for sensitive operations)
   - **Admin consent display name**: Access API as user
   - **Admin consent description**: Allows the app to access the API on behalf of the signed-in user
   - **User consent display name**: Access API as you
   - **User consent description**: Allows the app to access the API on your behalf
   - **State**: **Enabled**
5. Click **"Add scope"**
6. **Repeat step 4** to add more scopes if needed (e.g., `demo_oauth`, `api.write`, `api.admin`)

**Your final scopes will look like:**
- `api://4546d1ba-b797-41c6-af59-c7e198b59882/api.scope`
- `api://4546d1ba-b797-41c6-af59-c7e198b59882/demo_oauth`

**Note:** You only need to use the scope names (e.g., `api.scope`, `demo_oauth`) in your `.env` file - the application will automatically construct the full URIs!

#### Step 1.5: Configure App Roles (Optional - For Role-Based Access Control)

If you want to implement role-based access control (RBAC), you can define custom app roles:

1. Click **"App roles"** in the left menu
2. Click **"+ Create app role"** to add your first role:
   - **Display name**: Basic User
   - **Allowed member types**: **Users/Groups** (or Applications for service principals)
   - **Value**: `AppRole.BasicUser` (this is what appears in the token's `roles` claim)
   - **Description**: Basic user with read access
   - **Do you want to enable this app role?**: ✅ Checked
3. Click **"Apply"**
4. **Repeat step 2** to add more roles:
   - **Display name**: Admin User
   - **Value**: `AppRole.AdminUser`
   - **Description**: Administrator with full access
5. Click **"Apply"**

**Common role patterns:**
- `AppRole.BasicUser` - Basic access to the API
- `AppRole.AdminUser` - Administrative access
- `AppRole.ReadOnly` - Read-only access
- `AppRole.PowerUser` - Advanced features access

#### Step 1.6: Assign Roles to Users

After creating app roles, you need to assign them to users:

1. Go to **Azure Portal** → **Enterprise Applications** (not App Registrations!)
2. Find and click on your application
3. Click **"Users and groups"** in the left menu
4. Click **"+ Add user/group"**
5. Under **"Users"**, click **"None Selected"**
   - Search for and select the user
   - Click **"Select"**
6. Under **"Select a role"**, click **"None Selected"**
   - Choose a role (e.g., `AppRole.BasicUser`)
   - Click **"Select"**
7. Click **"Assign"**

**To assign multiple roles to the same user:**
- Repeat steps 4-7, selecting the **same user** but a **different role** each time
- The user will appear multiple times in the list, once for each role
- Their token will contain all assigned roles in the `roles` claim:
  ```json
  "roles": ["AppRole.BasicUser", "AppRole.AdminUser"]
  ```

**Alternative: Use PowerShell for bulk assignments:**
```powershell
Connect-AzureAD

$userId = "user-object-id"
$servicePrincipalId = "enterprise-app-object-id"

# Get all app roles
$appRoles = Get-AzureADServicePrincipal -ObjectId $servicePrincipalId | Select-Object -ExpandProperty AppRoles

# Assign BasicUser role
$basicRole = $appRoles | Where-Object { $_.Value -eq "AppRole.BasicUser" }
New-AzureADUserAppRoleAssignment -ObjectId $userId -PrincipalId $userId -ResourceId $servicePrincipalId -Id $basicRole.Id

# Assign AdminUser role to the same user
$adminRole = $appRoles | Where-Object { $_.Value -eq "AppRole.AdminUser" }
New-AzureADUserAppRoleAssignment -ObjectId $userId -PrincipalId $userId -ResourceId $servicePrincipalId -Id $adminRole.Id
```

#### Step 1.7: Add Platform Configuration (Optional)

For better security and tracking:

1. Still in **"Authentication"**, click **"+ Add a platform"**
2. Select **"Mobile and desktop applications"**
3. Check the redirect URI:
   - `https://login.microsoftonline.com/common/oauth2/nativeclient`
4. Click **"Configure"**

### Summary of Required Azure Settings

| Setting | Location | Value | Required? |
|---------|----------|-------|-----------|
| **Public client flows** | Authentication → Advanced settings | **Yes** | ✅ Required |
| **API Permissions** | API permissions | `User.Read` | ✅ Required |
| **Application ID URI** | Expose an API | `api://{client-id}` | ✅ Required |
| **API Scopes** | Expose an API → Scopes | `api.scope`, `demo_oauth`, etc. | ✅ Required (at least 1) |
| **App Roles** | App roles | `AppRole.BasicUser`, `AppRole.AdminUser` | Optional (for RBAC) |
| **Role Assignments** | Enterprise Applications → Users and groups | Assign roles to users | Optional (for RBAC) |
| **Platform config** | Authentication → Platforms | Mobile and desktop | Optional |

### 2. Install Dependencies

```bash
# Install using pip
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

### 3. Configure Environment Variables

Copy the example environment file and update with your values:

```bash
# Copy the example file
cp env.example .env

# Edit .env with your values
```

Required variables:
```env
TENANT_ID=your-tenant-id-here      # From Azure Portal
CLIENT_ID=your-client-id-here      # From Azure Portal
API_SCOPES=api.scope demo_oauth    # Your API scope names (space-separated)
```

**Important:** `API_SCOPES` uses just the scope names (not full URIs). The application automatically constructs full URIs like `api://client-id/api.scope`.

Examples:
- Single scope: `API_SCOPES=api.scope`
- Multiple scopes: `API_SCOPES=api.scope demo_oauth`
- Custom scope: `API_SCOPES=api.read api.write`

Optional variables:
```env
AUDIENCE=api://your-client-id      # Expected audience in token
TOKEN_VERSION=v2.0                 # v1.0 or v2.0
DEBUG=False                        # Enable debug mode
PORT=8000                          # Server port
```

### 4. Run the Application

```bash
# Run using Python
python -m src.main

# Or run using uvicorn directly
uvicorn src.main:app --reload

# Or run with custom host/port
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

The API will be available at:
- Application: http://localhost:8000
- API Documentation: http://localhost:8000/docs
- ReDoc Documentation: http://localhost:8000/redoc

## Usage

### Getting an Access Token

To test the API, you need an access token from Entra ID. The application provides built-in endpoints using **Device Code Flow** - the industry-standard method for CLIs and testing.

#### ⭐ Device Code Flow (Built-in)

The **easiest and recommended way** to get a token:

```bash
# 1. Get device code
curl http://localhost:8000/auth/device-code

# 2. Visit https://microsoft.com/devicelogin in your browser
#    Enter the user_code displayed

# 3. Get your token (use device_code from step 1)
curl -X POST http://localhost:8000/auth/device-token \
  -H "Content-Type: application/json" \
  -d '{"device_code": "YOUR_DEVICE_CODE"}'
```

#### Alternative: Using Azure CLI
```bash
az login
az account get-access-token --resource api://your-client-id
```

#### Alternative: Using Postman
1. Create a new request
2. Go to Authorization tab
3. Type: OAuth 2.0
4. Configure with your Azure AD details
5. Get New Access Token

**Note:** For production web applications, authentication should be handled by your frontend (React/Angular) using Authorization Code + PKCE flow. Your FastAPI backend only validates tokens.

### Making API Requests

#### Public Endpoints (No Authentication)

```bash
# Health check
curl http://localhost:8000/health

# Root endpoint
curl http://localhost:8000/
```

#### Protected Endpoints (Requires JWT)

```bash
# Replace YOUR_TOKEN with your actual access token

# Get protected resource
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/protected

# Get user profile
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/user/profile

# Get user permissions
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/user/permissions

# Get sample data
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/data/sample
```

### Example Response

```json
{
  "message": "Access granted to protected resource",
  "user": {
    "subject": "00000000-0000-0000-0000-000000000000",
    "name": "John Doe",
    "email": "john.doe@company.com",
    "tenant_id": "your-tenant-id",
    "scopes": ["api.read", "api.write"],
    "roles": []
  }
}
```

## Architecture

### Singleton Pattern

The application uses singleton pattern for:

1. **Settings** (`get_settings()`) - Single configuration instance using `@lru_cache()`
2. **JWTValidator** - Single validator instance managing JWKS cache

### Authentication Flow

1. Client sends request with `Authorization: Bearer <token>` header
2. FastAPI security extracts the token
3. `get_token_payload()` dependency validates the token:
   - Fetches JWKS from Entra ID (with caching)
   - Verifies token signature using public key
   - Validates issuer, audience, expiration
   - Validates custom claims (tenant, version, scopes)
4. `get_current_user()` extracts user information from validated payload
5. Endpoint receives authenticated user object

### JWT Validation

The validator performs comprehensive checks:
- ✅ Signature verification using RS256 algorithm
- ✅ Issuer validation (matches expected Entra ID issuer)
- ✅ Audience validation (matches configured client ID)
- ✅ Expiration time (exp claim)
- ✅ Not before time (nbf claim)
- ✅ Token version validation
- ✅ Tenant ID validation
- ✅ Required scopes validation (if configured)

## API Endpoints

### Public Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root endpoint with API information |
| `/health` | GET | Health check endpoint |
| `/docs` | GET | Interactive API documentation (Swagger) |
| `/redoc` | GET | Alternative API documentation (ReDoc) |

### Protected Endpoints (Require Authentication)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/protected` | GET | Basic protected endpoint demonstrating auth |
| `/api/user/profile` | GET | Get authenticated user's profile |
| `/api/user/permissions` | GET | Get user's scopes and roles |
| `/api/data/sample` | GET | Sample data endpoint |

## Advanced Usage

### Understanding Scopes vs Roles

**OAuth 2.0 Scopes:**
- Define **what the application can do** on behalf of the user
- Configured in "Expose an API" → Scopes
- Appear in token's `scp` claim (space-separated string)
- Example: `"scp": "api.scope demo_oauth"`
- **Used for:** Ensuring token was requested for your API (validated during device code flow)

**Azure AD App Roles:**
- Define **who the user is** and what they can access
- Configured in "App roles" → Create app role
- Appear in token's `roles` claim (array of strings)
- Example: `"roles": ["AppRole.BasicUser", "AppRole.AdminUser"]`
- **Used for:** Authorization - controlling access to specific endpoints

**This application's approach:**
- **Scopes** are validated automatically (users must have valid API scopes to get a token)
- **Roles** are used for endpoint authorization (`require_role()`, `require_any_role()`)
- Clean and simple - roles provide all the access control you need

### Using Role-Based Access Control (RBAC)

The application supports Azure AD app roles for fine-grained access control:

```python
from fastapi import Depends
from src.auth import require_role, require_any_role, get_current_user

# Require specific role
@app.get("/api/admin")
async def admin_endpoint(
    current_user = Depends(get_current_user),
    _: None = Depends(require_role("AppRole.AdminUser"))
):
    return {"message": "Admin access granted"}

# Require any of multiple roles
@app.get("/api/data")
async def data_endpoint(
    _: None = Depends(require_any_role("AppRole.BasicUser", "AppRole.AdminUser"))
):
    return {"data": "protected data"}
```

**How it works:**
1. Users are assigned app roles in Azure Portal (Enterprise Applications → Users and groups)
2. Token's `roles` claim contains assigned roles: `["AppRole.BasicUser", "AppRole.AdminUser"]`
3. FastAPI dependencies validate roles before allowing access

### Checking User Permissions in Code

```python
from src.models import User

@app.get("/api/resource")
async def resource_endpoint(current_user: User = Depends(get_current_user)):
    # Check if user has specific role
    if current_user.has_role("AppRole.AdminUser"):
        return {"message": "Admin access", "admin": True}
    
    # Check if user has specific scope
    if current_user.has_scope("api.scope"):
        return {"message": "Has API scope", "can_access": True}
    
    # Use convenience properties
    if current_user.is_admin:
        return {"message": "Admin user detected"}
    
    return {"message": "Basic access"}
```

## Development

### Code Quality

```bash
# Format code
black src/

# Lint code
ruff check src/
```

### Testing

```bash
# Run tests (when implemented)
pytest

# Run tests with coverage
pytest --cov=src tests/
```

## Security Considerations

1. **Never log tokens** - Tokens are sensitive credentials
2. **Use HTTPS in production** - Always use TLS/SSL
3. **Validate all claims** - Don't skip validation steps
4. **Keep dependencies updated** - Regularly update security packages
5. **Use proper CORS settings** - Configure appropriate origins
6. **Monitor token expiration** - Handle token refresh properly
7. **Implement rate limiting** - Protect against abuse (not included in this example)

## Troubleshooting

### Common Token Validation Issues

#### "Unable to fetch OpenID configuration"

- Check your `TENANT_ID` is correct
- Ensure network connectivity to login.microsoftonline.com
- Verify firewall/proxy settings

#### "Token validation failed: Invalid audience"

- Ensure `CLIENT_ID` matches the token's `aud` claim
- If using custom audience, set `AUDIENCE` environment variable to match the token's `aud` claim
- **Common fix:** Your token might have `"aud": "api://client-id"` but your `.env` has just the client ID
  - Solution: Set `AUDIENCE=api://your-client-id` in `.env`
  - Or the code will automatically add `api://` prefix if not set

#### "Token validation failed: Invalid issuer"

- Verify `TENANT_ID` is correct
- **Check token version:** Look at the `"ver"` claim in your token
  - v1.0 tokens: `"iss": "https://sts.windows.net/{tenant-id}/"`
  - v2.0 tokens: `"iss": "https://login.microsoftonline.com/{tenant-id}/v2.0"`
- **Solution:** Set `TOKEN_VERSION=v1.0` or `TOKEN_VERSION=v2.0` in `.env` to match your token
- The application now automatically handles both v1.0 and v2.0 token formats

#### "Token version mismatch. Expected 1.0, got 1"

- This was a bug in the version validation logic (now fixed)
- Ensure you have the latest code that properly compares version strings
- Set `TOKEN_VERSION=v1.0` in `.env` for v1.0 tokens

#### "Unable to find an algorithm for key"

- This was a bug in the JWKS key construction (now fixed)
- The application now automatically adds `"alg": "RS256"` to JWK keys if missing
- Ensure you have the latest code with this fix

#### "Signature verification failed"

- Token might be expired (check `exp` claim)
- Token might be corrupted
- JWKS might be outdated (will auto-refresh after TTL)
- Ensure token was issued by the correct tenant

### Token Debugging Tips

1. **Decode your token** at [jwt.ms](https://jwt.ms) to see all claims
2. **Check these claims match your configuration:**
   - `aud` (audience) → Should match `AUDIENCE` or `api://CLIENT_ID`
   - `iss` (issuer) → Should match expected issuer based on `TOKEN_VERSION`
   - `ver` (version) → Should be "1.0" or "2.0", match with `TOKEN_VERSION`
   - `tid` (tenant ID) → Should match `TENANT_ID`
   - `scp` (scopes) → Should contain your API scopes
   - `roles` → Should contain assigned app roles (if using RBAC)
3. **Check expiration:** Ensure token hasn't expired (`exp` claim)
4. **Verify role assignments:** Go to Enterprise Applications → Users and groups to see assigned roles

## References

- [Microsoft Identity Platform Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/)
- [Access Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [OpenID Connect](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
- [Azure AD App Roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)
- [OAuth 2.0 Scopes](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)

## Quick Reference

### Token Claims Reference

| Claim | Description | Example |
|-------|-------------|---------|
| `aud` | Audience - who the token is for | `"api://4546d1ba-b797-41c6-af59-c7e198b59882"` |
| `iss` | Issuer - who issued the token | `"https://sts.windows.net/{tenant-id}/"` (v1.0) |
| `tid` | Tenant ID | `"a29f1550-7848-4264-b780-2874985f7fb0"` |
| `oid` | Object ID of the user | `"0fe29e0f-8040-496a-9a5a-72932c15aae0"` |
| `sub` | Subject - unique user identifier | `"QLtj8k3bz3fIvWzmZPqZAS7W..."` |
| `scp` | Scopes - delegated permissions | `"api.scope demo_oauth"` (space-separated) |
| `roles` | App roles assigned to user | `["AppRole.BasicUser", "AppRole.AdminUser"]` |
| `ver` | Token version | `"1.0"` or `"2.0"` |
| `exp` | Expiration time (Unix timestamp) | `1761285561` |
| `nbf` | Not before time (Unix timestamp) | `1761281653` |
| `iat` | Issued at time (Unix timestamp) | `1761281653` |

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TENANT_ID` | ✅ Yes | - | Azure AD Tenant ID |
| `CLIENT_ID` | ✅ Yes | - | Application Client ID |
| `API_SCOPES` | ✅ Yes | - | Space-separated API scopes |
| `AUDIENCE` | No | `api://{CLIENT_ID}` | Expected audience in token |
| `TOKEN_VERSION` | No | `v2.0` | Token version: `v1.0` or `v2.0` |
| `DEBUG` | No | `False` | Enable debug logging |
| `PORT` | No | `8000` | Server port |
| `JWKS_CACHE_TTL` | No | `86400` | JWKS cache TTL in seconds |

### Common Patterns

**Token Version Detection:**
- v1.0 tokens: `"iss": "https://sts.windows.net/{tenant}/"`, `"ver": "1.0"`
- v2.0 tokens: `"iss": "https://login.microsoftonline.com/{tenant}/v2.0"`, `"ver": "2.0"`

**Audience Format:**
- With api:// prefix: `"aud": "api://4546d1ba-b797-41c6-af59-c7e198b59882"`
- Without prefix: `"aud": "4546d1ba-b797-41c6-af59-c7e198b59882"`
- Set `AUDIENCE` to match your token's `aud` claim exactly

**Role Assignment:**
- Single role: User appears once in Enterprise App → Users and groups
- Multiple roles: User appears multiple times, once per role
- Token contains all roles: `"roles": ["AppRole.BasicUser", "AppRole.AdminUser"]`


