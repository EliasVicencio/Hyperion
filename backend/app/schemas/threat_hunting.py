from enum import Enum

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SIEMProvider(str, Enum):
    SPLUNK = "SPLUNK"
    SENTINEL = "SENTINEL"
    GENERIC = "GENERIC"


class RawEventPayload(BaseModel):
    provider: SIEMProvider
    raw_data: dict = Field(..., description="JSON intacto enviado por el webhook")


class NormalizedThreatEvent(BaseModel):
    event_id: str = Field(..., description="ID único normalizado")
    provider: SIEMProvider
    timestamp: str = Field(..., description="Timestamp en ISO format")
    severity: SeverityLevel
    source_ip: str | None = Field(default="0.0.0.0")
    destination_ip: str | None = Field(default="0.0.0.0")
    rule_name: str = Field(..., description="Regla o consulta que gatilló la alerta")
    description: str | None = None
    raw_payload: dict = Field(default_factory=dict, description="Payload original para auditoría")


class ThreatHuntingQueryResult(BaseModel):
    total_matched: int
    threats: list[NormalizedThreatEvent]
    time_taken_ms: float