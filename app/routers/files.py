import os
import uuid

from app.schemas import file
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from app.database import get_db
from app.models.file import File as FileModel, ShareToken, FilePermission
from app.models.user import User
from app.schemas.file import FileOut, ShareTokenCreate, ShareTokenOut
from app.core.crypto import encrypt_file, decrypt_file, hash_file
from app.core.scanner import scan_file
from app.core.audit import log_event
from app.config import settings
from fastapi.security import OAuth2PasswordBearer

router = APIRouter(prefix="/files", tags=["Files"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Blocked MIME types — reject these outright
BLOCKED_MIME = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sh",
    "application/x-shellscript",
    "text/x-shellscript",
    "application/x-msdos-program",
}

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB


# ── Helper: get current user from JWT ────────────────────────────────────────
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ── POST /files/upload ────────────────────────────────────────────────────────
@router.post("/upload", response_model=FileOut, status_code=201)
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Read file into memory
    data = await file.read()

    # 1. Size check
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")

    # 2. MIME type detection (real type, not just extension)
    mime = magic.from_buffer(data, mime=True)
    if MAGIC_AVAILABLE:
        mime = magic.from_buffer(data, mime=True)
    else:
        mime = file.content_type or "application/octet-stream"
    if mime in BLOCKED_MIME:
        log_event("UPLOAD_BLOCKED_MIME", current_user.id, {"mime": mime, "filename": file.filename})
        raise HTTPException(status_code=400, detail=f"File type '{mime}' is not allowed")

    # 3. Compute SHA-256 hash of plaintext BEFORE encryption
    file_hash = hash_file(data)

    # 4. VirusTotal scan
    scan_result = scan_file(data)
    is_malicious = scan_result.get("is_malicious", False)
    if is_malicious:
        log_event("UPLOAD_BLOCKED_MALWARE", current_user.id, {
            "filename": file.filename,
            "detections": scan_result.get("detections")
        })
        raise HTTPException(status_code=400, detail="File flagged as malicious by antivirus scan")

    # 5. Encrypt with AES-256-GCM using user's ID as password seed
    encrypted_blob = encrypt_file(data, current_user.id)

    # 6. Store with random UUID filename (hides original name on disk)
    stored_name = f"{uuid.uuid4()}.enc"
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(settings.UPLOAD_DIR, stored_name)
    with open(file_path, "wb") as f:
        f.write(encrypted_blob)

    # 7. Save metadata to DB
    db_file = FileModel(
        original_name=file.filename,
        stored_name=stored_name,
        file_hash=file_hash,
        file_size=len(data),
        mime_type=mime,
        is_malicious=is_malicious,
        owner_id=current_user.id
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    log_event("FILE_UPLOADED", current_user.id, {
        "file_id": db_file.id,
        "filename": file.filename,
        "size": len(data),
        "mime": mime
    })
    return db_file


# ── GET /files/ ───────────────────────────────────────────────────────────────
@router.get("/", response_model=list[FileOut])
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(FileModel).filter(FileModel.owner_id == current_user.id).all()


# ── GET /files/download/{file_id} ─────────────────────────────────────────────
@router.get("/download/{file_id}")
def download_file(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_file = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")

    # Only owner can download directly
    if db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Read encrypted blob from disk
    file_path = os.path.join(settings.UPLOAD_DIR, db_file.stored_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File missing from storage")

    with open(file_path, "rb") as f:
        encrypted_blob = f.read()

    # Decrypt
    try:
        plaintext = decrypt_file(encrypted_blob, current_user.id)
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed — file may be corrupted")

    # Integrity check — compare SHA-256
    if hash_file(plaintext) != db_file.file_hash:
        log_event("INTEGRITY_FAILURE", current_user.id, {"file_id": file_id})
        raise HTTPException(status_code=500, detail="Integrity check failed — file has been tampered with")

    log_event("FILE_DOWNLOADED", current_user.id, {"file_id": file_id})

    # Stream file back to client
    return StreamingResponse(
        iter([plaintext]),
        media_type=db_file.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{db_file.original_name}"'}
    )


# ── POST /files/share/{file_id} ───────────────────────────────────────────────
@router.post("/share/{file_id}", response_model=ShareTokenOut)
def create_share_link(
    file_id: str,
    payload: ShareTokenCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_file = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not db_file or db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    expires_at = None
    if payload.expires_hours:
        expires_at = datetime.utcnow() + timedelta(hours=payload.expires_hours)

    token = ShareToken(
        token=str(uuid.uuid4()),
        file_id=file_id,
        creator_id=current_user.id,
        permission=payload.permission,
        max_downloads=payload.max_downloads,
        expires_at=expires_at
    )
    db.add(token)
    db.commit()
    db.refresh(token)

    log_event("SHARE_LINK_CREATED", current_user.id, {
        "file_id": file_id,
        "token": token.token,
        "expires_at": str(expires_at)
    })
    return token


# ── GET /files/shared/{token} ─────────────────────────────────────────────────
@router.get("/shared/{token}")
def download_shared(token: str, db: Session = Depends(get_db)):
    share = db.query(ShareToken).filter(ShareToken.token == token).first()

    if not share:
        raise HTTPException(status_code=404, detail="Share link not found")
    if share.is_revoked:
        raise HTTPException(status_code=403, detail="Share link has been revoked")
    if share.expires_at and datetime.utcnow() > share.expires_at:
        raise HTTPException(status_code=403, detail="Share link has expired")
    if share.max_downloads != -1 and share.download_count >= share.max_downloads:
        raise HTTPException(status_code=403, detail="Download limit reached")

    db_file = share.file

    file_path = os.path.join(settings.UPLOAD_DIR, db_file.stored_name)
    with open(file_path, "rb") as f:
        encrypted_blob = f.read()

    # Decrypt using owner's ID
    try:
        plaintext = decrypt_file(encrypted_blob, db_file.owner_id)
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")

    # Integrity check
    if hash_file(plaintext) != db_file.file_hash:
        log_event("INTEGRITY_FAILURE", share.creator_id, {"file_id": db_file.id})
        raise HTTPException(status_code=500, detail="Integrity check failed")

    # Increment download counter
    share.download_count += 1
    db.commit()

    log_event("SHARED_FILE_DOWNLOADED", share.creator_id, {
        "file_id": db_file.id,
        "token": token,
        "download_count": share.download_count
    })

    return StreamingResponse(
        iter([plaintext]),
        media_type=db_file.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{db_file.original_name}"'}
    )


# ── DELETE /files/{file_id} ───────────────────────────────────────────────────
@router.delete("/{file_id}")
def delete_file(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_file = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not db_file or db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Delete encrypted file from disk
    file_path = os.path.join(settings.UPLOAD_DIR, db_file.stored_name)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.delete(db_file)
    db.commit()

    log_event("FILE_DELETED", current_user.id, {"file_id": file_id})
    return {"message": "File deleted successfully"}