import os
import asyncio
import httpx

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")

# Solo se notifica a partir de esta severidad, para no saturar los canales
# con eventos rutinarios (ej. un LOGIN_FAILED aislado es WARN, no CRITICAL).
NOTIFY_MIN_SEVERITY = os.getenv("NOTIFY_MIN_SEVERITY", "CRITICAL").upper()
_SEVERITY_ORDER = {"INFO": 0, "WARN": 1, "CRITICAL": 2}

_ESTILO = {
    "CRITICAL": {"hex": 0xDC2626, "slack": "#dc2626", "emoji": "🔴"},
    "WARN": {"hex": 0xD97706, "slack": "#d97706", "emoji": "🟡"},
    "INFO": {"hex": 0x2563EB, "slack": "#2563eb", "emoji": "🔵"},
}


def _slack_payload(titulo, operador, accion, detalles, categoria):
    e = _ESTILO.get(categoria, _ESTILO["INFO"])
    return {
        "attachments": [{
            "color": e["slack"],
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"{e['emoji']} *{titulo}*"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Operador:*\n{operador}"},
                    {"type": "mrkdwn", "text": f"*Acción:*\n{accion}"},
                ]},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": detalles or "Sin detalles adicionales."}]},
            ],
        }]
    }


def _discord_payload(titulo, operador, accion, detalles, categoria):
    e = _ESTILO.get(categoria, _ESTILO["INFO"])
    return {
        "embeds": [{
            "title": f"{e['emoji']} {titulo}",
            "color": e["hex"],
            "fields": [
                {"name": "Operador", "value": operador or "—", "inline": True},
                {"name": "Acción", "value": accion, "inline": True},
                {"name": "Detalles", "value": detalles or "Sin detalles adicionales.", "inline": False},
            ],
        }]
    }


def _teams_payload(titulo, operador, accion, detalles, categoria):
    # Formato Adaptive Card requerido por los webhooks de Teams Workflows
    # (los webhooks clásicos de Office 365 Connectors ya fueron retirados por Microsoft).
    e = _ESTILO.get(categoria, _ESTILO["INFO"])
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": f"{e['emoji']} {titulo}", "size": "Large", "weight": "Bolder"},
                    {"type": "FactSet", "facts": [
                        {"title": "Operador", "value": operador or "—"},
                        {"title": "Acción", "value": accion},
                        {"title": "Detalles", "value": detalles or "Sin detalles adicionales."},
                    ]},
                ],
            },
        }],
    }


async def notificar_evento(operador: str, accion: str, categoria: str, detalles: str = None):
    """Envía el evento a Slack, Discord y Teams (los que estén configurados vía env vars).
    Best-effort: nunca lanza excepciones hacia arriba. Un webhook caído o mal configurado
    no debe romper el flujo normal de auditoría/login/lo que sea que disparó el evento."""
    categoria = (categoria or "INFO").upper()
    if _SEVERITY_ORDER.get(categoria, 0) < _SEVERITY_ORDER.get(NOTIFY_MIN_SEVERITY, 2):
        return
    if not any([SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL, TEAMS_WEBHOOK_URL]):
        return

    titulo = "Alerta de Seguridad Hyperion" if categoria == "CRITICAL" else "Aviso de Hyperion"

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            tareas = []
            if SLACK_WEBHOOK_URL:
                tareas.append(client.post(SLACK_WEBHOOK_URL, json=_slack_payload(titulo, operador, accion, detalles, categoria)))
            if DISCORD_WEBHOOK_URL:
                tareas.append(client.post(DISCORD_WEBHOOK_URL, json=_discord_payload(titulo, operador, accion, detalles, categoria)))
            if TEAMS_WEBHOOK_URL:
                tareas.append(client.post(TEAMS_WEBHOOK_URL, json=_teams_payload(titulo, operador, accion, detalles, categoria)))

            resultados = await asyncio.gather(*tareas, return_exceptions=True)
            for r in resultados:
                if isinstance(r, Exception):
                    print(f"⚠️ Notificación fallida (no crítico, no interrumpe el flujo): {r}")
                elif hasattr(r, "status_code") and r.status_code >= 300:
                    print(f"⚠️ Webhook respondió {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"⚠️ Error inesperado enviando notificaciones (no crítico): {e}")