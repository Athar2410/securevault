from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.models.user import User
from app.schemas.user import UserRegister, TokenResponse, MFASetupResponse, UserOut
from app.core.security import (
    hash_password, verify_password, create_access_token,
    generate_mfa_secret, get_mfa_qr, verify_totp
)
from app.core.audit import log_event
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
limiter = Limiter(key_func=get_remote_address)


# ── Register ──────────────────────────────────────────────────────────────────
@router.post("/register", response_model=UserOut, status_code=201)
@limiter.limit("5/minute")
def register(request: Request, payload: UserRegister, db: Session = Depends(get_db)):
    # Check uniqueness
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Password strength check
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_event("USER_REGISTERED", user.id, {"username": user.username})
    return user


# ── Login ─────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, payload: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()

    # Generic error — don't leak whether user exists
    if not user or not verify_password(payload.password, user.hashed_password):
        log_event("LOGIN_FAILED", "unknown", {"username": payload.username})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    # If MFA is enabled, signal client to prompt for TOTP
    if user.mfa_enabled:
        log_event("LOGIN_MFA_REQUIRED", user.id, {})
        return TokenResponse(access_token="", mfa_required=True)

    user.last_login = datetime.utcnow()
    db.commit()
    token = create_access_token({"sub": user.id, "username": user.username})
    log_event("LOGIN_SUCCESS", user.id, {})
    return TokenResponse(access_token=token, mfa_required=False)


# ── MFA Login (step 2) ────────────────────────────────────────────────────────
@router.post("/login/mfa", response_model=TokenResponse)
@limiter.limit("10/minute")
def login_mfa(request: Request, username: str, totp_token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA not configured for this user")

    if not verify_totp(user.mfa_secret, totp_token):
        log_event("MFA_FAILED", user.id, {})
        raise HTTPException(status_code=401, detail="Invalid or expired TOTP token")

    user.last_login = datetime.utcnow()
    db.commit()
    token = create_access_token({"sub": user.id, "username": user.username})
    log_event("LOGIN_MFA_SUCCESS", user.id, {})
    return TokenResponse(access_token=token)


# ── MFA Setup ─────────────────────────────────────────────────────────────────
@router.post("/mfa/setup", response_model=MFASetupResponse)
def setup_mfa(request: Request, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    from jose import JWTError, jwt
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = generate_mfa_secret()
    user.mfa_secret = secret
    db.commit()

    qr = get_mfa_qr(user.username, secret)
    log_event("MFA_SETUP_INITIATED", user.id, {})
    return MFASetupResponse(secret=secret, qr_code=qr)


# ── MFA Confirm (verify and enable) ──────────────────────────────────────────
@router.post("/mfa/confirm")
def confirm_mfa(request: Request, totp_token: str, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    from jose import JWTError, jwt
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="Run /mfa/setup first")

    if not verify_totp(user.mfa_secret, totp_token):
        raise HTTPException(status_code=401, detail="Invalid TOTP — check your authenticator app")

    user.mfa_enabled = True
    db.commit()
    log_event("MFA_ENABLED", user.id, {})
    return {"message": "MFA successfully enabled"}


# ── Disable MFA ───────────────────────────────────────────────────────────────
@router.post("/mfa/disable")
@limiter.limit("3/minute")
def disable_mfa(request: Request, totp_token: str, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Disable MFA — requires valid TOTP to prevent unauthorized disable."""
    from jose import JWTError, jwt
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    # Must verify current TOTP before disabling — prevents attacker with stolen JWT from disabling MFA
    if not verify_totp(user.mfa_secret, totp_token):
        log_event("MFA_DISABLE_FAILED", user.id, {})
        raise HTTPException(status_code=401, detail="Invalid TOTP token")

    user.mfa_enabled = False
    user.mfa_secret = None
    db.commit()
    log_event("MFA_DISABLED", user.id, {})
    return {"message": "MFA disabled successfully"}


# ── Get Current User Profile ──────────────────────────────────────────────────
@router.get("/me", response_model=UserOut)
def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Get currently authenticated user's profile."""
    from jose import JWTError, jwt
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user