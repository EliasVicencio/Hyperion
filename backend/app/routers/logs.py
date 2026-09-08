from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..core import get_current_user, get_db

router = APIRouter(
    prefix="/logs",
    tags=["Logs & Auditoría"]
)


@router.get("", status_code=status.HTTP_200_OK)
@router.get("/", status_code=status.HTTP_200_OK)
async def get_logs(
    limit: int = Query(default=50, ge=1, le=500),
    categoria: str | None = Query(default=None, description="Filtro por categoría: INFO, WARN, CRITICAL"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Obtiene la lista de logs de auditoría reales desde la tabla
    logs_auditoria en PostgreSQL (Supabase), más recientes primero.
    """
    try:
        if categoria:
            query = text("""
                SELECT id, operador, accion, categoria, origen_ip, detalles, timestamp
                FROM logs_auditoria
                WHERE UPPER(categoria) = UPPER(:categoria)
                ORDER BY id DESC
                LIMIT :limit
            """)
            filas = db.execute(query, {"categoria": categoria, "limit": limit}).fetchall()
        else:
            query = text("""
                SELECT id, operador, accion, categoria, origen_ip, detalles, timestamp
                FROM logs_auditoria
                ORDER BY id DESC
                LIMIT :limit
            """)
            filas = db.execute(query, {"limit": limit}).fetchall()

        return [
            {
                "id": fila.id,
                "operador": fila.operador,
                "accion": fila.accion,
                "categoria": fila.categoria,
                "origen_ip": fila.origen_ip,
                "detalles": fila.detalles,
                "timestamp": fila.timestamp.isoformat() if fila.timestamp else None,
            }
            for fila in filas
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al recuperar los logs desde la base de datos: {e!s}"
        )