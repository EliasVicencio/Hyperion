import os

import psycopg2
from fastapi import APIRouter, HTTPException, Request
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel

# Importa las funciones y el mapeo de estados de tu servicio de Jira
from app.services.jira_service import (
    JIRA_STATUS_MAP,
    create_jira_issue,
    transition_jira_issue,
)

router = APIRouter(prefix="/tickets", tags=["Tickets"])


def get_db_connection():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise HTTPException(status_code=500, detail="DATABASE_URL no configurada")
    return psycopg2.connect(database_url, cursor_factory=RealDictCursor)


# --- MODELOS PYDANTIC ---
class TicketCreate(BaseModel):
    titulo: str
    descripcion: str | None = ""
    prioridad: str | None = "Media"


# --- ENDPOINTS ---

@router.get("")
@router.get("/")
async def get_tickets():
    """Obtiene todos los tickets de Supabase."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM public.tickets ORDER BY id DESC;")
        tickets = cursor.fetchall()
        cursor.close()
        conn.close()
        return tickets
    except Exception as e:
        print(f"Error al obtener tickets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("")
@router.post("/")
async def create_ticket(ticket: TicketCreate):
    """Crea un ticket en Supabase y lo envía a Jira (Outbound)."""
    try:
        jira_res = await create_jira_issue(
            title=ticket.titulo,
            description=ticket.descripcion,
            priority=ticket.prioridad,
        )
        # Si Jira no está configurado o falla, seguimos creando el ticket
        # localmente igual (degradación controlada, no bloqueamos al usuario).
        jira_key = jira_res.get("key") if jira_res else None
        jira_url = jira_res.get("url") if jira_res else None

        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO public.tickets (titulo, descripcion, prioridad, estado, jira_issue_key, jira_issue_url)
            VALUES (%s, %s, %s, 'ABIERTO', %s, %s)
            RETURNING *;
        """
        cursor.execute(query, (ticket.titulo, ticket.descripcion, ticket.prioridad, jira_key, jira_url))
        nuevo_ticket = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        return nuevo_ticket
    except Exception as e:
        print(f"Error al crear ticket: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{ticket_id}")
@router.patch("/{ticket_id}/")
async def update_ticket(ticket_id: int, payload: dict):
    """Actualiza campos de un ticket (típicamente el estado) en Supabase.

    Nota: esto solo actualiza el estado en Hyperion. No empuja el cambio
    de vuelta a Jira (eso requeriría la API de transiciones de Jira,
    que es un endpoint distinto al de creación). La sincronización
    Jira -> Hyperion sigue funcionando vía /tickets/webhook/jira.
    """
    campos_permitidos = {"estado", "titulo", "descripcion", "prioridad"}
    actualizaciones = {k: v for k, v in payload.items() if k in campos_permitidos}

    if not actualizaciones:
        raise HTTPException(status_code=400, detail="No se recibió ningún campo válido para actualizar.")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        set_clause = ", ".join(f"{campo} = %s" for campo in actualizaciones)
        valores = [*actualizaciones.values(), ticket_id]

        query = f"""
            UPDATE public.tickets
            SET {set_clause}
            WHERE id = %s
            RETURNING *;
        """
        cursor.execute(query, valores)
        ticket_actualizado = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if not ticket_actualizado:
            raise HTTPException(status_code=404, detail=f"No existe un ticket con id {ticket_id}.")

        # Sincronización Hyperion -> Jira: si cambiamos el estado y el ticket
        # está vinculado a un issue de Jira, intentamos transicionarlo también.
        # Best-effort: si Jira falla, el ticket queda igual actualizado en
        # Hyperion, solo avisamos en la respuesta que no se pudo sincronizar.
        jira_sync_ok = None
        nuevo_estado = actualizaciones.get("estado")
        jira_key = ticket_actualizado.get("jira_issue_key")
        if nuevo_estado and jira_key:
            jira_sync_ok = await transition_jira_issue(jira_key, nuevo_estado)

        return {**ticket_actualizado, "jira_sync_ok": jira_sync_ok}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error al actualizar ticket {ticket_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{ticket_id}")
@router.delete("/{ticket_id}/")
async def delete_ticket(ticket_id: int):
    """Elimina un ticket de Supabase. No elimina el issue vinculado en Jira."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM public.tickets WHERE id = %s RETURNING id;",
            (ticket_id,),
        )
        eliminado = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if not eliminado:
            raise HTTPException(status_code=404, detail=f"No existe un ticket con id {ticket_id}.")

        return {"status": "deleted", "id": ticket_id}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error al eliminar ticket {ticket_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhook/jira")
async def jira_webhook(request: Request):
    """Webhook receptor de actualizaciones desde Jira (Inbound)."""
    try:
        payload = await request.json()
        print("--- WEBHOOK RECIBIDO DE JIRA ---")

        issue = payload.get("issue", {})
        jira_key = issue.get("key")

        if not jira_key:
            return {"status": "ignored", "reason": "No issue key in payload"}

        fields = issue.get("fields", {})
        status_data = fields.get("status", {})

        raw_status = str(status_data.get("name", "")).strip().upper()
        nuevo_estado = JIRA_STATUS_MAP.get(raw_status, "ABIERTO")

        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            UPDATE public.tickets 
            SET estado = %s 
            WHERE jira_issue_key = %s
            RETURNING id, titulo, estado, jira_issue_key;
        """
        cursor.execute(query, (nuevo_estado, jira_key))
        updated_ticket = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        if updated_ticket:
            return {
                "status": "success",
                "jira_key": jira_key,
                "raw_status": raw_status,
                "nuevo_estado": nuevo_estado,
                "updated_ticket": updated_ticket,
            }

        return {
            "status": "unlinked",
            "message": f"Sin coincidencias en BD para {jira_key}",
        }

    except Exception as e:
        print(f"ERROR EN WEBHOOK: {e}")
        raise HTTPException(status_code=500, detail=f"Webhook Error: {e!s}")