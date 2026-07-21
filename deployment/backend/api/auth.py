"""
MaKeVaslim Panel - Authentication API
"""
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from pydantic import BaseModel

from ..auth import (
    get_current_user, require_auth, require_admin, login_user, logout_user,
    get_password_hash, set_password_hash, verify_password,
    set_session_cookie, clear_session_cookie, create_session
)
from ..database import get_db, DatabaseManager, User

router = APIRouter(prefix="/api", tags=["Auth"])


class LoginRequest(BaseModel):
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/login")
async def api_login(request: Request, response: Response, data: LoginRequest):
    """Login with panel password."""
    db = await get_db()
    password = data.password

    password_hash = await get_password_hash(db)
    if not password_hash:
        # First login - set password
        await set_password_hash(db, password)
        token = await create_session("admin")
        set_session_cookie(response, token)
        return {"success": True, "token": token}

    if not verify_password(password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    token = await create_session("admin")
    set_session_cookie(response, token)
    return {"success": True, "token": token}


@router.post("/logout")
async def api_logout(request: Request, response: Response):
    await logout_user(request, response)
    return {"success": True}


@router.get("/me")
async def api_me(user: User = Depends(get_current_user)):
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "username": user.username,
        "is_admin": True,
    }


@router.post("/change-password")
async def api_change_password(data: ChangePasswordRequest, user: User = Depends(require_auth)):
    db = await get_db()
    current_hash = await get_password_hash(db)
    if not verify_password(data.current_password, current_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")

    if len(data.new_password) < 4:
        raise HTTPException(status_code=400, detail="New password must be at least 4 characters")

    await set_password_hash(db, data.new_password)
    return {"success": True}