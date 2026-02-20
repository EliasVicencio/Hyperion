from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True) # type: ignore
    username = Column(String(50), unique=True, index=True)
    password_hash = Column(String(255))
    totp_secret = Column(String(32))  # Secreto para el QR de Google Authenticator
    is_active = Column(Boolean, default=True)
    failed_attempts = Column(Integer, default=0)

class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, index=True) # type: ignore
    user_id = Column(Integer, ForeignKey("users.id"))
    ip_address = Column(String(45))
    event = Column(String(50)) # ej: 'login_success', 'blocked_ip'
    created_at = Column(DateTime, default=datetime.utcnow)