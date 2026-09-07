import datetime

from fastapi import APIRouter, status
from sqlalchemy import text

from ..core import engine

router = APIRouter(
    prefix="/health",
    tags=["Health Check"]
)


def _verificar_conexion_bd() -> str:
    """
    Intenta una query mínima (SELECT 1) contra la base de datos.
    Devuelve 'connected' o 'disconnected'. Nunca lanza excepción:
    un fallo de BD no debe tumbar el endpoint de health.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "connected"
    except Exception as e:
        print(f"🚨 Health check: fallo de conexión a BD: {e!s}")
        return "disconnected"


@router.get("", status_code=status.HTTP_200_OK)
@router.get("/", status_code=status.HTTP_200_OK)
async def check_health():
    """
    Endpoint de verificación de estado operativo.
    Retorna 200 OK si el backend FastAPI está en línea, e incluye
    el estado real de la conexión a la base de datos en 'database'.
    """
    db_status = _verificar_conexion_bd()
    return {
        "status": "healthy",
        "database": db_status,
        "service": "Hyperion Core Backend",
        "version": "2.0.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }