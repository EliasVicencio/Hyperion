import os
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..core import get_db, get_current_user, registrar_log
from ..notifications import notificar_ticket

router = APIRouter(prefix="/api/v1/tickets", tags=["Tickets"])

TICKETS_API_KEY = os.getenv("TICKETS_API_KEY")

PRIORIDADES_VALIDAS = {"BAJA", "MEDIA", "ALTA", "CRITICA"}
ESTADOS_VALIDOS = {"ABIERTO", "CERRADO"}


class NuevoTicket(BaseModel):
    titulo: str = Field(..., min_length=3, max_length=200)
    descripcion: str | None = None
    prioridad: str = "MEDIA"


class NuevoTicketExterno(NuevoTicket):
    solicitante: str = Field(..., description="Nombre o email de quien reporta, ya que no hay sesión de Hyperion")


class ActualizarTicket(BaseModel):
    estado: str


def _validar_prioridad(prioridad: str) -> str:
    p = (prioridad or "MEDIA").upper()
    if p not in PRIORIDADES_VALIDAS:
        raise HTTPException(status_code=422, detail=f"Prioridad inválida. Usa una de: {', '.join(PRIORIDADES_VALIDAS)}")
    return p


async def _crear_ticket_en_bd(db: Session, titulo: str, descripcion: str, prioridad: str, creado_por: str, origen: str):
    query = text("""
        INSERT INTO tickets (titulo, descripcion, prioridad, estado, creado_por, origen)
        VALUES (:titulo, :descripcion, :prioridad, 'ABIERTO', :creado_por, :origen)
        RETURNING id, titulo, descripcion, prioridad, estado, creado_por, origen, created_at
    """)
    try:
        row = db.execute(query, {
            "titulo": titulo,
            "descripcion": descripcion,
            "prioridad": prioridad,
            "creado_por": creado_por,
            "origen": origen,
        }).fetchone()
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")

    ticket = {
        "id": row[0], "titulo": row[1], "descripcion": row[2], "prioridad": row[3],
        "estado": row[4], "creado_por": row[5], "origen": row[6],
        "created_at": row[7].strftime("%Y-%m-%d %H:%M:%S") if hasattr(row[7], "strftime") else row[7],
    }

    await notificar_ticket(ticket)
    await registrar_log(db, creado_por, "TICKET_CREATED", "INFO", detalles=f"Ticket #{ticket['id']} ({prioridad}): {titulo}")

    return ticket


@router.post("", status_code=201)
async def crear_ticket(payload: NuevoTicket, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Crea un ticket desde dentro de Hyperion (requiere sesión activa)."""
    prioridad = _validar_prioridad(payload.prioridad)
    return await _crear_ticket_en_bd(db, payload.titulo, payload.descripcion, prioridad, current_user["email"], "INTERNO")


@router.post("/external", status_code=201)
async def crear_ticket_externo(
    payload: NuevoTicketExterno,
    db: Session = Depends(get_db),
    x_api_key: str = Header(None, alias="X-API-Key"),
):
    """Crea un ticket desde un sistema externo, sin sesión de Hyperion.
    Requiere el header X-API-Key con el valor de TICKETS_API_KEY."""
    if not TICKETS_API_KEY:
        raise HTTPException(status_code=500, detail="TICKETS_API_KEY no está configurada en el backend.")
    if not x_api_key or x_api_key != TICKETS_API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida o ausente (header X-API-Key).")

    prioridad = _validar_prioridad(payload.prioridad)
    return await _crear_ticket_en_bd(db, payload.titulo, payload.descripcion, prioridad, payload.solicitante, "API_EXTERNA")


@router.get("")
async def listar_tickets(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Lista todos los tickets, más recientes primero."""
    try:
        query = text("""
            SELECT id, titulo, descripcion, prioridad, estado, creado_por, origen, created_at
            FROM tickets ORDER BY created_at DESC LIMIT 200
        """)
        rows = db.execute(query).fetchall()
        return [
            {
                "id": r[0], "titulo": r[1], "descripcion": r[2], "prioridad": r[3],
                "estado": r[4], "creado_por": r[5], "origen": r[6],
                "created_at": r[7].strftime("%Y-%m-%d %H:%M:%S") if hasattr(r[7], "strftime") else r[7],
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")


@router.patch("/{ticket_id}")
async def actualizar_ticket(ticket_id: int, payload: ActualizarTicket, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Cambia el estado de un ticket (ABIERTO / CERRADO)."""
    estado = (payload.estado or "").upper()
    if estado not in ESTADOS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"Estado inválido. Usa uno de: {', '.join(ESTADOS_VALIDOS)}")

    try:
        result = db.execute(
            text("UPDATE tickets SET estado = :estado WHERE id = :id RETURNING id"),
            {"estado": estado, "id": ticket_id},
        )
        row = result.fetchone()
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")

    if not row:
        raise HTTPException(status_code=404, detail=f"No existe el ticket #{ticket_id}.")

    await registrar_log(db, current_user["email"], "TICKET_UPDATED", "INFO", detalles=f"Ticket #{ticket_id} → {estado}")
    return {"id": ticket_id, "estado": estado}