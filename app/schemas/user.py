from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str
    totp_token: Optional[str] = None  # required if MFA enabled

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: bool = False

class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str   # base64 PNG

class UserOut(BaseModel):
    id: str
    username: str
    email: str
    mfa_enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True