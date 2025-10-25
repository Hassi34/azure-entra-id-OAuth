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
