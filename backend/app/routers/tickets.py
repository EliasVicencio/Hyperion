import os

import psycopg2
from fastapi import APIRouter, HTTPException, Request
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel

# Importa tu función de servicio de Jira
from app.services.jira_service import create_jira_issue

router = APIRouter(prefix="/tickets", tags=["Tickets"])

# --- MAPPING JIRA -> HYPERION ---
JIRA_STATUS_MAP = {
    # CERRADO
    "DONE": "CERRADO",
    "RESOLVED": "CERRADO",
    "CLOSED": "CERRADO",
    "FINALIZADA": "CERRADO",
    "MARCAR COMO HECHO": "CERRADO",
    "LISTO": "CERRADO",
    "RESUELTO": "CERRADO",
    "CERRADO": "CERRADO",
    
    # EN PROCESO
    "IN PROGRESS": "EN PROCESO",
    "WORK IN PROGRESS": "EN PROCESO",
    "EN CURSO": "EN PROCESO",
    "EN PROCESO": "EN PROCESO",
    "COMENZAR PROGRESO": "EN PROCESO",
    "PROGRESS": "EN PROCESO",
    
    # ABIERTO
    "TO DO": "ABIERTO",
    "OPEN": "ABIERTO",
    "POR HACER": "ABIERTO",
    "PENDIENTE": "ABIERTO",
    "ABIERTA": "ABIERTO",
    "REOPENED": "ABIERTO",
}


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
async def create_ticket(ticket: TicketCreate):
    """Crea un ticket en Supabase y lo envía a Jira (Outbound)."""
    try:
        jira_res = create_jira_issue(
            summary=ticket.titulo,
            description=ticket.descripcion,
            priority=ticket.prioridad,
        )
        jira_key = jira_res.get("key")

        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO public.tickets (titulo, descripcion, prioridad, estado, jira_issue_key)
            VALUES (%s, %s, %s, 'ABIERTO', %s)
            RETURNING *;
        """
        cursor.execute(query, (ticket.titulo, ticket.descripcion, ticket.prioridad, jira_key))
        nuevo_ticket = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        return nuevo_ticket
    except Exception as e:
        print(f"Error al crear ticket: {e}")
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