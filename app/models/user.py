from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username     = Column(String, unique=True, nullable=False, index=True)
    email        = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)

    # MFA
    mfa_secret   = Column(String, nullable=True)
    mfa_enabled  = Column(Boolean, default=False)

    # Account state
    is_active    = Column(Boolean, default=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    last_login   = Column(DateTime, nullable=True)

    # Relationships
    files        = relationship("File", back_populates="owner", cascade="all, delete")
    share_tokens = relationship("ShareToken", back_populates="creator", cascade="all, delete")