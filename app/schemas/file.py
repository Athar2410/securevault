from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from app.models.file import FilePermission

class FileOut(BaseModel):
    id: str
    original_name: str
    file_size: int
    mime_type: str
    is_malicious: bool
    created_at: datetime

    class Config:
        from_attributes = True

class ShareTokenCreate(BaseModel):
    file_id: str
    permission: FilePermission = FilePermission.viewer
    max_downloads: int = 5
    expires_hours: Optional[int] = 24   # None = no expiry

class ShareTokenOut(BaseModel):
    token: str
    expires_at: Optional[datetime]
    max_downloads: int
    permission: FilePermission