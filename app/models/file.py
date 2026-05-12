from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid, enum
from app.database import Base

class FilePermission(str, enum.Enum):
    owner  = "owner"
    editor = "editor"
    viewer = "viewer"

class File(Base):
    __tablename__ = "files"

    id               = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    original_name    = Column(String, nullable=False)         # real filename
    stored_name      = Column(String, nullable=False)         # encrypted UUID name on disk
    file_hash        = Column(String, nullable=False)         # SHA-256 of plaintext
    file_size        = Column(Integer, nullable=False)
    mime_type        = Column(String, nullable=False)
    is_malicious     = Column(Boolean, default=False)         # VirusTotal result
    owner_id         = Column(String, ForeignKey("users.id"), nullable=False)
    created_at       = Column(DateTime, default=datetime.utcnow)

    owner            = relationship("User", back_populates="files")
    share_tokens     = relationship("ShareToken", back_populates="file", cascade="all, delete")


class ShareToken(Base):
    __tablename__ = "share_tokens"

    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    token         = Column(String, unique=True, nullable=False, index=True)
    file_id       = Column(String, ForeignKey("files.id"), nullable=False)
    creator_id    = Column(String, ForeignKey("users.id"), nullable=False)
    permission    = Column(Enum(FilePermission), default=FilePermission.viewer)
    max_downloads = Column(Integer, default=5)            # -1 = unlimited
    download_count= Column(Integer, default=0)
    expires_at    = Column(DateTime, nullable=True)       # None = no expiry
    is_revoked    = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow)

    file          = relationship("File", back_populates="share_tokens")
    creator       = relationship("User", back_populates="share_tokens")