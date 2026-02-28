import requests
import time

BASE_URL = "http://localhost:8000"  # Ajusta si tu puerto es distinto
API_KEY_FINANCE = "finance-app-key-123"
API_KEY_HR = "hr-app-key-456"

def send_log(api_key, service, event, actor, target, context):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    payload = {
        "source": service,
        "event_type": event,
        "actor": actor,
        "target": target,
        "context": context
    }
    try:
        response = requests.post(f"{BASE_URL}/api/v1/ingest/log", json=payload, headers=headers)
        if response.status_code == 200:
            print(f"✅ Log enviado ({service}): {event} - Index: {response.json().get('index')}")
        else:
            print(f"❌ Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"🚨 Conexión fallida: {e}")

# --- SIMULACIÓN DE ACTIVIDAD CORPORATIVA ---

print("🚀 Iniciando inyección de logs corporativos en Hyperion SIEM...\n")

# Eventos de Finanzas
send_log(API_KEY_FINANCE, "finance_service", "PAYMENT_BATCH_PROCESSED", "system_bot", "ledger_2026", {"amount": 55000, "status": "approved"})
time.sleep(1)
send_log(API_KEY_FINANCE, "finance_service", "UNAUTHORIZED_ACCESS_ATTEMPT", "unknown_user", "vault_alpha", {"ip": "192.168.1.50"})

# Eventos de RRHH
time.sleep(1)
send_log(API_KEY_HR, "hr_service", "SALARY_UPDATE", "manager_ana", "employee_99", {"increase": "5%"})
time.sleep(1)
send_log(API_KEY_HR, "hr_service", "CONTRACT_SIGNED", "legal_dept", "new_hire_jdoe", {"doc_id": "PDF_992"})

print("\n✨ Inyección terminada. Revisa el Dashboard de Hyperion.")