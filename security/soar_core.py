import os
import sys
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text

# Forzar codificación UTF-8 para evitar errores de consola en Windows
if sys.platform.startswith("win"):
    import sys
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("[⚙️ SOAR BACKEND] Inicializando Motor de Respuesta con Gestión de Falsos Positivos...")

# 1. Configuración de Conexión Segura
DB_URL = "postgresql://postgres.tyunqthoinamdlyhgmuq:zKxaQ4y2zNtaMnI3@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
engine = create_engine(DB_URL)

def is_in_allowlist(target, target_type):
    """
    Verifica de forma segura si una IP o Usuario está protegido por la lista blanca corporativa.
    """
    query = text("""
        SELECT COUNT(*) FROM security_allowlist 
        WHERE target = :target AND target_type = :target_type
    """)
    try:
        with engine.connect() as conn:
            result = conn.execute(query, {"target": target, "target_type": target_type}).scalar()
            return result > 0
    except Exception as e:
        print(f"[❌ ERROR ALLOWLIST]: No se pudo verificar la exclusión para {target}: {e}")
        return False

def execute_autonomous_playbook(severity, source_ip=None, user_email=None, threat_detail="Actividad Anómala"):
    """
    Orquesta la respuesta adaptativa autónoma verificando políticas de exclusión (Falsos Positivos).
    """
    print(f"\n[⚡ SOAR] Evaluando Playbook Autónomo para severidad: {severity.upper()}")
    
    # --- PASO 1: VERIFICACIÓN CONTRA LA LISTA BLANCA CORPORATIVA ---
    is_ip_safe = is_in_allowlist(source_ip, 'ip') if source_ip else False
    is_user_safe = is_in_allowlist(user_email, 'user') if user_email else False

    if is_ip_safe or is_user_safe:
        protected_target = source_ip if is_ip_safe else user_email
        reason_type = "IP_EXEMPT" if is_ip_safe else "USER_EXEMPT"
        
        print(f"[🛡️ MUTED EVENT]: Alerta contra {protected_target} SILENCIADA de forma segura por política corporativa.")
        
        # Insertar registro de evasión segura en el Ledger Inmutable para auditorías externas
        log_action = f"MUTED_EVENT: {threat_detail} detectado en {protected_target}, pero la contención autónoma fue omitida por regla en Allowlist."
        try:
            with engine.connect() as conn:
                with conn.begin():
                    conn.execute(
                        text('INSERT INTO "audit_logs" (actor, action) VALUES (:actor, :action)'),
                        {"actor": "HYPERION_SOAR_POLICY", "action": log_action}
                    )
            print("[+] SOAR [METRIC]: Evento exceptuado inyectado correctamente en el Ledger.")
        except Exception as e:
            print(f"[❌ LEDGER ERROR]: Falló la escritura del evento exceptuado: {e}")
        return  # Terminamos el playbook de forma limpia sin ejecutar bloqueos

    # --- PASO 2: LOGICA DE MITIGACIÓN AUTÓNOMA ESTÁNDAR (Si no está en lista blanca) ---
    try:
        with engine.connect() as conn:
            with conn.begin():
                # Rastro inmutable en el Ledger
                log_action = f"AUTONOMOUS_CONTAINMENT: Playbook {severity.upper()} desplegado contra "
                targets = []
                if source_ip: targets.append(f"IP {source_ip}")
                if user_email: targets.append(f"Usuario {user_email}")
                log_action += " y ".join(targets) + f" por {threat_detail}."

                conn.execute(
                    text('INSERT INTO "audit_logs" (actor, action) VALUES (:actor, :action)'),
                    {"actor": "HYPERION_AUTONOMOUS", "action": log_action}
                )
                print("[+] SOAR [METRIC]: Alerta de contención inyectada en el Ledger Inmutable.")

                # Reglas de contención dinámicas según la severidad
                now = datetime.now()
                duration = 60 if severity.lower() in ['critical', 'high'] else 30
                expires = now + timedelta(minutes=duration)

                # 1. Bloqueo Perimetral (Firewall)
                if source_ip:
                    conn.execute(text("""
                        INSERT INTO firewall_network_blocks (blocked_ip, duration_minutes, expires_at, reason)
                        VALUES (:ip, :duration, :expires, :reason)
                        ON CONFLICT (blocked_ip) DO UPDATE SET expires_at = :expires
                    """), {"ip": source_ip, "duration": duration, "expires": expires, "reason": f"SOAR: {threat_detail} ({severity})"})
                    print(f"[🔒 FIREWALL]: IP {source_ip} bloqueada dinámicamente por {duration} minutos. Expira: {expires.strftime('%H:%M:%S')}.")

                # 2. Destrucción de Sesiones Críticas (JWT Revocation)
                if user_email and severity.lower() in ['critical', 'high']:
                    conn.execute(text("""
                        INSERT INTO jwt_blacklist (user_email, reason)
                        VALUES (:email, :reason)
                        ON CONFLICT (user_email) DO NOTHING
                    """), {"email": user_email, "reason": f"Expulsión SOAR Automática: {threat_detail}"})
                    print(f"[❌ JWT_REVOCATION]: Sesión de {user_email} destruida de raíz. Credenciales en lista negra.")

                # 3. Notificación de Emergencia Extensible (Crisis Webhook Sim)
                if severity.lower() == 'critical':
                    print("[🚨 CRISIS_MODE]: Playbook de Incidente Mayor activado. Notificando CSIRT vía Webhook Securo.")

    except Exception as e:
        print(f"[❌ SOAR EXECUTION CRASH]: Error crítico ejecutando contención autónoma: {e}")

if __name__ == "__main__":
    # Prueba de concepto interna del backend para validar que discrimina correctamente
    print("\n--- TEST 1: Ejecutando ataque desde IP Legítima (Falso Positivo en Lista Blanca) ---")
    execute_autonomous_playbook("critical", source_ip="192.168.1.50", threat_detail="Simulación de escaneo de vulnerabilidades de backup")

    print("\n--- TEST 2: Ejecutando ataque desde IP Hostil (Ciberataque Real) ---")
    execute_autonomous_playbook("critical", source_ip="198.51.100.44", user_email="malicious_actor@shadow.com", threat_detail="Inyección SQL masiva detectada por Darktrace")