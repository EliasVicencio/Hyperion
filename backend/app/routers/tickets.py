import os
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from app.services.jira_service import create_jira_issue

router = APIRouter(prefix="/api/v1/tickets", tags=["Tickets"])

DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL no está configurada")
    url = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    return psycopg2.connect(url, cursor_factory=RealDictCursor)

class TicketCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: Optional[str] = "Media"

@router.get("")
def get_tickets():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM public.tickets ORDER BY created_at DESC;")
        tickets = cursor.fetchall()
        cursor.close()
        conn.close()
        return tickets
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener tickets: {str(e)}")

@router.post("")
async def create_ticket(ticket: TicketCreate):
    if not ticket.title:
        raise HTTPException(status_code=400, detail="El título del ticket es requerido.")

    # 1. Crear el ticket en Jira de forma asíncrona
    jira_data = await create_jira_issue(
        title=ticket.title,
        description=ticket.description,
        priority=ticket.priority
    )

    jira_key = jira_data.get("key") if jira_data else None
    jira_url = jira_data.get("url") if jira_data else None

    # 2. Insertar en la base de datos Supabase
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO public.tickets 
            (title, description, priority, status, jira_issue_key, jira_issue_url)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *;
        """
        cursor.execute(
            query, 
            (ticket.title, ticket.description, ticket.priority, "Abierto", jira_key, jira_url)
        )
        new_ticket = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        return {
            "status": "success",
            "message": "Ticket registrado exitosamente",
            "ticket": new_ticket
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al guardar ticket en BD: {str(e)}")