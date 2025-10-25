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
