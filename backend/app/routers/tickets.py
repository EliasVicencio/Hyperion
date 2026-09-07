import os

import psycopg2
from fastapi import APIRouter, HTTPException, Request
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel

# Asegúrate de importar tu servicio de Jira desde jira_service.py
from app.services.jira_service import create_jira_issue

router = APIRouter(prefix="/tickets", tags=["Tickets"])

# --- DICCIONARIO AMPLIADO DE ESTADOS (MAPPING JIRA -> HYPERION) ---
JIRA_STATUS_MAP = {
    # CERRADO / FINALIZADO
    "DONE": "CERRADO",
    "RESOLVED": "CERRADO",
    "CLOSED": "CERRADO",
    "FINALIZADA": "CERRADO",
    "MARCAR COMO HECHO": "CERRADO",
    "LISTO": "CERRADO",
    "RESUELTO": "CERRADO",
    "CERRADO": "CERRADO",
    
    # EN PROCESO / EN CURSO
    "IN PROGRESS": "EN PROCESO",
    "WORK IN PROGRESS": "EN PROCESO",
    "EN CURSO": "EN PROCESO",
    "EN PROCESO": "EN PROCESO",
    "COMENZAR PROGRESO": "EN PROCESO",
    "PROGRESS": "EN PROCESO",
    
    # ABIERTO / PENDIENTE
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
    """ Obtiene todos los tickets registrados en la base de datos """
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
    """ Crea un ticket localmente y lo sincroniza en Jira (Outbound) """
    try:
        # 1. Crear issue en Jira Service Management
        jira_res = create_jira_issue(
            summary=ticket.titulo,
            description=ticket.descripcion,
            priority=ticket.prioridad
        )
        jira_key = jira_res.get("key")

        # 2. Guardar registro en Supabase
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
    """ Endpoint receptor de Webhooks desde Jira (Inbound Sync) """
    try:
        payload = await request.json()
        print("--- WEBHOOK RECIBIDO DE JIRA ---")
        
        issue = payload.get("issue", {})
        jira_key = issue.get("key")  # Ej: "DEV-2"

        if not jira_key:
            return {"status": "ignored", "reason": "No issue key found in payload"}

        fields = issue.get("fields", {})
        status_data = fields.get("status", {})
        
        # Normalizamos la cadena del estado recibida desde Jira
        raw_status = str(status_data.get("name", "")).strip().upper()
        
        # Mapeamos al estado interno de Hyperion
        nuevo_estado = JIRA_STATUS_MAP.get(raw_status, "ABIERTO")
        
        print(f"ISSUE: {jira_key} | JIRA RAW STATUS: '{raw_status}' -> MAPEA A: '{nuevo_estado}'")

        # Actualizamos el registro correspondiente en la BD
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
            print(f"EXITO: Ticket ID {updated_ticket['id']} actualizado a {nuevo_estado}")
            return {
                "status": "success",
                "jira_key": jira_key,
                "raw_status": raw_status,
                "nuevo_estado": nuevo_estado,
                "updated_ticket": updated_ticket
            }

        print(f"ADVERTENCIA: No se encontró ticket con jira_issue_key = '{jira_key}'")
        return {
            "status": "not_found",
            "message": f"Ticket con key {jira_key} no existe en la BD local"
        }

    except Exception as e:
        print(f"ERROR CRÍTICO EN WEBHOOK JIRA: {e}")
        raise HTTPException(status_code=500, detail=f"Internal Webhook Error: {e!s}")