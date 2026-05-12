import pyotp, qrcode, io, base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta
from jose import JWTError, jwt
from app.config import settings

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, plain)
    except VerifyMismatchError:
        return False

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def get_mfa_qr(username: str, secret: str) -> str:
    """Returns base64-encoded QR code PNG for authenticator apps."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="SecureVault"
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def verify_totp(secret: str, token: str) -> bool:
    return pyotp.TOTP(secret).verify(token)