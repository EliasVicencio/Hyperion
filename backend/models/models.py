from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
import enum
from ..database import Base  # O la ruta donde tengas tu Base

class IncidentSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default=IncidentSeverity.MEDIUM)
    status = Column(String(20), default=IncidentStatus.OPEN)
    source_ip = Column(String(50), nullable=True)
    assigned_to = Column(String(100), default="L1 Analyst")
    playbook_action = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)