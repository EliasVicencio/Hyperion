from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi.concurrency import run_in_threadpool
from datetime import datetime
from ..core import get_db, RAW_DB_URL, get_current_user

router = APIRouter(prefix="/api/v1", tags=["Logs"])

@router.get("/logs")
async def get_logs_auditoria(categoria: str | None = None, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL no configurada.")
    try:
        if categoria:
            query = text("SELECT id, timestamp, operador, accion, categoria, origen_ip, detalles FROM logs_auditoria WHERE categoria = :categoria ORDER BY timestamp DESC LIMIT 100")
            result = await run_in_threadpool(db.execute, query, {"categoria": categoria.upper()})
        else:
            query = text("SELECT id, timestamp, operador, accion, categoria, origen_ip, detalles FROM logs_auditoria ORDER BY timestamp DESC LIMIT 100")
            result = await run_in_threadpool(db.execute, query)
        rows = result.fetchall()
        lista_logs = []
        for row in rows:
            lista_logs.append({
                "id": row[0],
                "timestamp": row[1].strftime("%Y-%m-%d %H:%M:%S") if row[1] else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "operador": row[2],
                "accion": row[3],
                "categoria": row[4],
                "origen_ip": row[5],
                "detalles": row[6] if row[6] else ""
            })
        return lista_logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al consultar logs: {str(e)}")
