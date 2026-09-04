from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import text
from sqlalchemy.orm import Session

# Importamos el cliente de Supabase desde tus servicios
from app.services.supabase_client import supabase_client
from ..core import RAW_DB_URL, get_current_user, get_db

router = APIRouter(prefix="/api/v1", tags=["Logs"])


@router.get("/logs")
async def get_logs_auditoria(
    categoria: str | None = None,
    limit: int = Query(
        50, ge=1, le=200, description="Cantidad de registros por página"
    ),
    page: int = Query(1, ge=1, description="Número de página a consultar"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL no configurada.")

    offset = (page - 1) * limit

    try:
        if categoria:
            query = text("""
                SELECT id, timestamp, operador, accion, categoria, origen_ip, detalles 
                FROM logs_auditoria 
                WHERE categoria = :categoria 
                ORDER BY timestamp DESC 
                LIMIT :limit OFFSET :offset
            """)
            result = await run_in_threadpool(
                db.execute,
                query,
                {"categoria": categoria.upper(), "limit": limit, "offset": offset},
            )
        else:
            query = text("""
                SELECT id, timestamp, operador, accion, categoria, origen_ip, detalles 
                FROM logs_auditoria 
                ORDER BY timestamp DESC 
                LIMIT :limit OFFSET :offset
            """)
            result = await run_in_threadpool(
                db.execute, query, {"limit": limit, "offset": offset}
            )

        rows = result.fetchall()
        lista_logs = []
        for row in rows:
            lista_logs.append(
                {
                    "id": row[0],
                    "timestamp": row[1].strftime("%Y-%m-%d %H:%M:%S")
                    if row[1]
                    else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "operador": row[2],
                    "accion": row[3],
                    "categoria": row[4],
                    "origen_ip": row[5],
                    "detalles": row[6] if row[6] else "",
                }
            )

        return {
            "page": page,
            "limit": limit,
            "total_items": len(lista_logs),
            "data": lista_logs,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al consultar logs: {e!s}")


@router.post("/logs")
async def create_log_auditoria(
    log_data: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Crea un log de auditoría y notifica en tiempo real vía Supabase Realtime."""
    try:
        # 1. Tu lógica habitual para guardar el log en PostgreSQL...
        
        # 2. Notificamos al frontend vía Supabase Realtime (si está configurado)
        if supabase_client:
            supabase_client.realtime.channel("hyperion-events").send_broadcast(
                event="telemetry",
                payload=log_data
            )

        return {"status": "success", "data": log_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al registrar log: {e!s}")