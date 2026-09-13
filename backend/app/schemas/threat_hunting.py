import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from app.schemas.threat_hunting import (
    NormalizedThreatEvent,
    RawEventPayload,
    SeverityLevel,
    SIEMProvider,
)

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])

# Mock temporal de la memoria/DB de amenazas
MOCK_THREAT_EVENTS: list[NormalizedThreatEvent] = []


def _process_siem_event(payload: RawEventPayload) -> NormalizedThreatEvent:
    """Parsea y normaliza la alerta recibida del SIEM según la fuente."""
    data = payload.raw_data

    if payload.provider == SIEMProvider.SPLUNK:
        # Formato Splunk HEC / Alert Rule
        return NormalizedThreatEvent(
            event_id=f"splunk-{uuid.uuid4().hex[:8]}",
            provider=SIEMProvider.SPLUNK,
            severity=data.get("severity", SeverityLevel.MEDIUM),
            source_ip=data.get("src_ip", "0.0.0.0"),
            destination_ip=data.get("dest_ip", "0.0.0.0"),
            rule_name=data.get("search_name", "Splunk Event Alert"),
            description=data.get("result", {}).get("_raw", "Alerta procesada desde Splunk"),
            raw_payload=data,
        )

    if payload.provider == SIEMProvider.SENTINEL:
        # Formato Microsoft Sentinel Log Analytics
        return NormalizedThreatEvent(
            event_id=f"sentinel-{uuid.uuid4().hex[:8]}",
            provider=SIEMProvider.SENTINEL,
            severity=data.get("Severity", SeverityLevel.HIGH),
            source_ip=data.get("SourceIPAddress", "0.0.0.0"),
            destination_ip=data.get("DestinationIPAddress", "0.0.0.0"),
            rule_name=data.get("Title", "Sentinel Incident"),
            description=data.get("Description", "Incidente de seguridad desde Sentinel"),
            raw_payload=data,
        )

    raise ValueError("Proveedor SIEM no soportado")


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_siem_event(
    payload: RawEventPayload, background_tasks: BackgroundTasks
):
    """Webhook público/autenticado para recibir alertas de Splunk o Sentinel."""
    try:
        normalized_event = _process_siem_event(payload)
        MOCK_THREAT_EVENTS.append(normalized_event)

        # Aquí enviaremos el evento por WebSocket en el Paso 2
        # background_tasks.add_task(broadcast_threat, normalized_event)

        return {
            "status": "accepted",
            "event_id": normalized_event.event_id,
            "provider": normalized_event.provider,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error procesando payload del SIEM: {e!s}",
        )


@router.get("/events", response_model=list[NormalizedThreatEvent])
async def get_threat_events(limit: int = 50):
    """Consulta la lista de eventos de amenazas detectados."""
    return MOCK_THREAT_EVENTS[:limit]