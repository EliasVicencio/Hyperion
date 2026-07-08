from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
from ..core import get_db, RAW_DB_URL

router = APIRouter(tags=["Health"])

@router.get("/health/deep")
async def deep_health(db: Session = Depends(get_db)):
    database_status = "connected"
    system_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        database_status = "disconnected"
        system_status = "unhealthy"
        print(f"🚨 ALERT: El chequeo de salud de la base de datos falló: {str(e)}")
    return {
        "status": system_status,
        "database": database_status,
        "has_db_url": bool(RAW_DB_URL),
        "timestamp": datetime.now().isoformat()
    }
