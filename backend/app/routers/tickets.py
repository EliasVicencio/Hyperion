import os

import psycopg2
from fastapi import APIRouter, HTTPException
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel

from app.services.jira_service import create_jira_issue

router = APIRouter(prefix="/api/v1/tickets", tags=["Tickets"])

DATABASE_URL = os.getenv("DATABASE_URL")


def get_db_connection():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL no está configurada")
    url = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    return psycopg2.connect(url, cursor_factory=RealDictCursor)


class TicketCreate(BaseModel):
    title: str | None = None
    titulo: str | None = None
    description: str | None = None
    descripcion: str | None = None
    priority: str | None = "MEDIA"
    prioridad: str | None = None

    @property
    def clean_title(self) -> str:
        return self.title or self.titulo or ""

    @property
    def clean_description(self) -> str:
        return self.description or self.descripcion or ""

    @property
    def clean_priority(self) -> str:
        return self.prioridad or self.priority or "MEDIA"


PRIORITY_MAP = {
    "BAJA": "Low",
    "MEDIA": "Medium",
    "ALTA": "High",
    "CRITICA": "Highest",
}


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
        raise HTTPException(status_code=500, detail=f"Error al obtener tickets: {e!s}")


@router.post("")
async def create_ticket(ticket: TicketCreate):
    title = ticket.clean_title
    description = ticket.clean_description
    raw_priority = ticket.clean_priority.upper()

    if not title:
        raise HTTPException(
            status_code=400, detail="El título del ticket es requerido."
        )

    jira_priority = PRIORITY_MAP.get(raw_priority, "Medium")

    # 1. Crear el ticket en Jira de forma asíncrona
    jira_data = await create_jira_issue(
        title=title, description=description, priority=jira_priority
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
            (
                title,
                description,
                raw_priority,
                "Abierto",
                jira_key,
                jira_url,
            ),
        )
        new_ticket = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()

        return {
            "status": "success",
            "message": "Ticket registrado exitosamente",
            "ticket": new_ticket,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error al guardar ticket en BD: {e!s}"
        )