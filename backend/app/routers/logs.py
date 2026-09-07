from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, status

router = APIRouter(
    prefix="/logs",
    tags=["Logs & Auditoría"]
)

# Mock temporal mientras no se consulte la base de datos directamente
MOCK_LOGS = [
    {
        "id": "log-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nivel": "INFO",
        "origen": "AuthService",
        "mensaje": "Usuario autenticado con éxito",
        "operador_id": "op-admin"
    },
    {
        "id": "log-002",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nivel": "WARNING",
        "origen": "ThreatIntel",
        "mensaje": "Intento de escaneo de puertos detectado",
        "operador_id": "system"
    }
]

@router.get("", status_code=status.HTTP_200_OK)
@router.get("/", status_code=status.HTTP_200_OK)
async def get_logs(
    limit: int = Query(default=50, ge=1, le=500),
    level: str | None = Query(default=None, description="Filtro por nivel: INFO, WARNING, ERROR")
):
    """
    Obtiene la lista de logs del sistema Hyperion.
    """
    try:
        resultado = MOCK_LOGS
        if level:
            resultado = [log for log in resultado if log["nivel"].upper() == level.upper()]
        
        return resultado[:limit]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al recuperar los logs: {e!s}"
        )