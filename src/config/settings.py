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
