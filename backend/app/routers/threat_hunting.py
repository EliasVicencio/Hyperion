import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect, status

from app.schemas.threat_hunting import (
    NormalizedThreatEvent,
    RawEventPayload,
    SeverityLevel,
    SIEMProvider,
)

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])

# Mock temporal en memoria
MOCK_THREAT_EVENTS: list[NormalizedThreatEvent] = []


# --- Gestor de Conexiones WebSocket ---
class ConnectionManager:
    """Administra las conexiones en tiempo real del Dashboard de Threat Hunting."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event: NormalizedThreatEvent) -> None:
        """Emite la amenaza detectada a todos los clientes/analistas conectados."""
        payload = event.model_dump_json()
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                # Si una conexión falla o se corta, se remueve limpiamente
                self.active_connections.remove(connection)


manager = ConnectionManager()


# --- Mapeo y Parsing de SIEMs ---
def _process_siem_event(payload: RawEventPayload) -> NormalizedThreatEvent:
    data = payload.raw_data

    if payload.provider == SIEMProvider.SPLUNK:
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


# --- Endpoints ---
@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_siem_event(
    payload: RawEventPayload, background_tasks: BackgroundTasks
):
    """Webhook para recibir alertas de SIEMs y transmitirlas en vivo."""
    try:
        normalized_event = _process_siem_event(payload)
        MOCK_THREAT_EVENTS.append(normalized_event)

        # Transmisión en segundo plano hacia el WebSocket
        background_tasks.add_task(manager.broadcast, normalized_event)

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


@router.websocket("/ws/live")
async def websocket_threat_stream(websocket: WebSocket):
    """Canal WebSocket en vivo para la vista de monitoreo del SOC / C-Level."""
    await manager.connect(websocket)
    try:
        while True:
            # Mantiene viva la conexión escuchando pings del cliente
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.get("/events", response_model=list[NormalizedThreatEvent])
async def get_threat_events(limit: int = 50):
    """Consulta histórica de eventos."""
    return MOCK_THREAT_EVENTS[:limit]