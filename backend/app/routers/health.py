import datetime

from fastapi import APIRouter, status

router = APIRouter(
    prefix="/health",
    tags=["Health Check"]
)

@router.get("", status_code=status.HTTP_200_OK)
@router.get("/", status_code=status.HTTP_200_OK)
async def check_health():
    """
    Endpoint de verificación de estado operativo.
    Retorna 200 OK si el backend FastAPI está en línea.
    """
    return {
        "status": "healthy",
        "service": "Hyperion Core Backend",
        "version": "2.0.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }