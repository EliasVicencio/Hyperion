import os
import httpx
from typing import Optional, Dict

JIRA_DOMAIN = os.getenv("JIRA_DOMAIN")        # Ej: "eliasvicencio.atlassian.net"
JIRA_EMAIL = os.getenv("JIRA_EMAIL")          # Tu correo de Atlassian
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")  # Token generado en Security
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "HYP") # Clave corta de tu proyecto (ej. HYP)

async def create_jira_issue(title: str, description: Optional[str] = None, priority: str = "Medium") -> Optional[Dict[str, str]]:
    """
    Crea un ticket en Jira Service Management / Jira Software vía API REST v3.
    Retorna un diccionario con 'key' y 'url' si la operación fue exitosa, o None en caso de fallo.
    """
    if not all([JIRA_DOMAIN, JIRA_EMAIL, JIRA_API_TOKEN]):
        print("⚠️ [JIRA] Faltan variables de entorno para Jira. Se omitirá la sincronización externa.")
        return None

    # Limpieza del dominio en caso de que incluya https://
    clean_domain = JIRA_DOMAIN.replace("https://", "").replace("http://", "").strip("/")
    url = f"https://{clean_domain}/rest/api/3/issue"
    auth = (JIRA_EMAIL, JIRA_API_TOKEN)

    # Formato Atlassian Document Format (ADF) requerido por la API v3
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
                                "text": description if description else "Sin descripción adicional provista desde Hyperion."
                            }
                        ]
                    }
                ]
            },
            "issuetype": {"name": "Task"}
        }
    }

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

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
        print(f"❌ [JIRA] Excepción durante la llamada HTTP: {str(e)}")
        return None