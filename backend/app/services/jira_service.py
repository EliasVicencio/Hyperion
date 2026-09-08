import os

import httpx

JIRA_DOMAIN = os.getenv("JIRA_DOMAIN")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "HYP")

# --- MAPPING JIRA -> HYPERION (fuente única de verdad) ---
# Los valores de salida deben coincidir EXACTO con los que usa el frontend
# (Tickets.jsx): 'ABIERTO', 'EN_PROCESO', 'RESUELTO'.
JIRA_STATUS_MAP = {
    # RESUELTO
    "DONE": "RESUELTO",
    "RESOLVED": "RESUELTO",
    "CLOSED": "RESUELTO",
    "FINALIZADA": "RESUELTO",
    "MARCAR COMO HECHO": "RESUELTO",
    "LISTO": "RESUELTO",
    "RESUELTO": "RESUELTO",
    "CERRADO": "RESUELTO",

    # EN_PROCESO
    "IN PROGRESS": "EN_PROCESO",
    "WORK IN PROGRESS": "EN_PROCESO",
    "EN CURSO": "EN_PROCESO",
    "EN PROCESO": "EN_PROCESO",
    "COMENZAR PROGRESO": "EN_PROCESO",
    "PROGRESS": "EN_PROCESO",

    # ABIERTO
    "TO DO": "ABIERTO",
    "OPEN": "ABIERTO",
    "POR HACER": "ABIERTO",
    "PENDIENTE": "ABIERTO",
    "ABIERTA": "ABIERTO",
    "REOPENED": "ABIERTO",
}


def _clean_domain() -> str:
    return (JIRA_DOMAIN or "").replace("https://", "").replace("http://", "").strip("/")


def _jira_configurado() -> bool:
    return all([JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN])


async def create_jira_issue(
    title: str, description: str | None = None, priority: str = "Medium"
) -> dict[str, str] | None:
    """Crea un ticket en Jira Service Management / Jira Software vía API REST v3."""
    if not all([JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN]):
        print("⚠️ [JIRA] Faltan variables de entorno para Jira. Se omitirá la sincronización externa.")
        return None

    clean_domain = JIRA_DOMAIN.replace("https://", "").replace("http://", "").strip("/")
    url = f"https://{clean_domain}/rest/api/3/issue"
    auth = (JIRA_EMAIL, JIRA_API_TOKEN)

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"[Hyperion] {title}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": description if description else "Sin descripción adicional provista desde Hyperion.",
                            }
                        ],
                    }
                ],
            },
            "issuetype": {"name": "Task"},
        }
    }

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload, auth=auth, headers=headers)

            if response.status_code == 201:
                data = response.json()
                issue_key = data.get("key")
                issue_url = f"https://{clean_domain}/browse/{issue_key}"
                print(f"✅ [JIRA] Ticket creado exitosamente: {issue_key}")
                return {"key": issue_key, "url": issue_url}
            else:
                print(f"❌ [JIRA] Error al crear ticket ({response.status_code}): {response.text}")
                return None
    except Exception as e:
        print(f"❌ [JIRA] Excepción durante la llamada HTTP: {e!s}")
        return None


async def transition_jira_issue(issue_key: str, target_estado_hyperion: str) -> bool:
    """
    Mueve un issue de Jira al estado que corresponde a `target_estado_hyperion`
    ('ABIERTO', 'EN_PROCESO' o 'RESUELTO'), sincronizando Hyperion -> Jira.

    Jira no tiene IDs de transición fijos (dependen del workflow de cada
    proyecto), así que primero consultamos las transiciones disponibles
    para ESE issue y elegimos la que apunte a un status que, según
    JIRA_STATUS_MAP, corresponda al estado que queremos en Hyperion.

    Devuelve True si la transición se aplicó, False si no se pudo
    (Jira no configurado, sin transición compatible disponible, o error
    de red). Nunca lanza excepción: un fallo de Jira no debe tumbar la
    actualización local del ticket en Hyperion.
    """
    if not _jira_configurado():
        print("⚠️ [JIRA] Faltan variables de entorno para Jira. Se omitirá la transición.")
        return False

    url = f"https://{_clean_domain()}/rest/api/3/issue/{issue_key}/transitions"
    auth = (JIRA_EMAIL, JIRA_API_TOKEN)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # 1) Consultar transiciones disponibles para este issue puntual
            response = await client.get(url, auth=auth, headers=headers)
            if response.status_code != 200:
                print(f"❌ [JIRA] No se pudieron obtener transiciones de {issue_key} ({response.status_code}): {response.text}")
                return False

            transiciones = response.json().get("transitions", [])

            # 2) Buscar una transición cuyo status destino mapee al estado que queremos
            transition_id = None
            for t in transiciones:
                nombre_status_destino = str(t.get("to", {}).get("name", "")).strip().upper()
                if JIRA_STATUS_MAP.get(nombre_status_destino) == target_estado_hyperion:
                    transition_id = t.get("id")
                    break

            if not transition_id:
                print(
                    f"⚠️ [JIRA] {issue_key}: no hay ninguna transición disponible hacia "
                    f"un estado equivalente a '{target_estado_hyperion}'. "
                    f"Transiciones disponibles: {[t.get('to', {}).get('name') for t in transiciones]}"
                )
                return False

            # 3) Ejecutar la transición
            post_response = await client.post(
                url, json={"transition": {"id": transition_id}}, auth=auth, headers=headers
            )
            if post_response.status_code == 204:
                print(f"✅ [JIRA] {issue_key} transicionado hacia estado equivalente a '{target_estado_hyperion}'.")
                return True

            print(f"❌ [JIRA] Falló la transición de {issue_key} ({post_response.status_code}): {post_response.text}")
            return False
    except Exception as e:
        print(f"❌ [JIRA] Excepción durante la transición de {issue_key}: {e!s}")
        return False