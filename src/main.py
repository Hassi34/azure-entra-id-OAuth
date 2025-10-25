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
