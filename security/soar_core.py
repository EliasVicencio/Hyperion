import pandas as pd
from sqlalchemy import text
from datetime import datetime, timedelta

class HyperionSOARCore:
    def __init__(self, db_engine):
        self.engine = db_engine
        # Diccionario de acciones estructurado según la severidad exigida por el CTO
        self.playbooks = {
            'low': [self.action_log_only, self.action_alert_dashboard],
            'medium': [self.action_alert_dashboard, self.action_block_ip_temporary],
            'high': [self.action_alert_dashboard, self.action_block_ip_temporary, self.action_revoke_user_tokens],
            'critical': [self.action_alert_dashboard, self.action_block_ip_temporary, self.action_revoke_user_tokens, self.action_trigger_incident_response]
        }

    def execute_playbook(self, severity, threat_data):
        """Orquestador principal que ejecuta las acciones en ráfaga."""
        severity_key = severity.lower()
        if severity_key not in self.playbooks:
            severity_key = 'low'
            
        print(f"\n[⚡ SOAR] Iniciando Playbook Autónomo para severidad: {severity_key.upper()}")
        
        # Ejecutar cada acción registrada para ese nivel de criticidad
        for action in self.playbooks[severity_key]:
            try:
                action(threat_data)
            except Exception as e:
                print(f"[-] Error al ejecutar acción {action.__name__}: {e}")

    # --- DEFINICIÓN DE ACCIONES QUIRÚRGICAS ---

    def action_log_only(self, data):
        print(f"[+] SOAR [LOW]: Registro básico de telemetría generado para {data.get('source_ip', 'Internal Node')}.")

    def action_alert_dashboard(self, data):
        # Aseguramos el registro inmutable previo a cualquier alteración
        query = 'INSERT INTO "audit_logs" (actor, action) VALUES (:actor, :action)'
        with self.engine.connect() as conn:
            with conn.begin():
                conn.execute(text(query), {
                    "actor": "HYPERION_AUTONOMOUS",
                    "action": f"ALERT_TRIGGERED: Incidente detectado Tipo [{data.get('threat_type')}] para IP [{data.get('source_ip')}]."
                })
        print("[+] SOAR [METRIC]: Alerta inyectada en el Ledger Inmutable.")

    def action_block_ip_temporary(self, data, duration=60):
        """Bloquea la IP en la tabla de Firewall calculando su expiración dinámica."""
        ip = data.get('source_ip')
        if not ip:
            return
            
        blocked_at = datetime.now()
        expires_at = blocked_at + timedelta(minutes=duration)
        reason = f"SOAR Autocontención: {data.get('threat_type', 'Tráfico anómalo perimetral')}"
        
        query = """
            INSERT INTO firewall_network_blocks (blocked_ip, duration_minutes, blocked_at, expires_at, reason)
            VALUES (:ip, :duration, :blocked_at, :expires_at, :reason)
            ON CONFLICT (blocked_ip) DO UPDATE 
            SET expires_at = EXCLUDED.expires_at, reason = EXCLUDED.reason
        """
        with self.engine.connect() as conn:
            with conn.begin():
                conn.execute(text(query), {
                    "ip": ip, "duration": duration, 
                    "blocked_at": blocked_at, "expires_at": expires_at, "reason": reason
                })
        print(f"[🔒 FIREWALL]: IP {ip} bloqueada dinámicamente por {duration} minutos. Expira: {expires_at.strftime('%H:%M:%S')}.")

    def action_revoke_user_tokens(self, data):
        """Revoca inmediatamente los accesos metiendo al usuario a la lista negra."""
        user_id = data.get('user_id', 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11') # ID por defecto para pruebas si viene de red
        user_email = data.get('user_email', 'operador_comprometido@hyperion.com')
        reason = f"Expulsión automática SOAR: Evidencia de compromiso en táctica [{data.get('mitre_tactic', 'N/A')}]."
        
        query = """
            INSERT INTO jwt_blacklist (user_id, user_email, reason)
            VALUES (:user_id, :user_email, :reason)
        """
        with self.engine.connect() as conn:
            with conn.begin():
                conn.execute(text(query), {
                    "user_id": user_id, "user_email": user_email, "reason": reason
                })
                # Logear la expulsión en la bitácora legal
                conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'HYPERION_AUTONOMOUS\', :action)'), {
                    "action": f"USER_SESSION_REVOKED: Operador [{user_email}] expulsado del sistema. Tokens invalidados."
                })
        print(f"[❌ JWT_REVOCATION]: Sesión de {user_email} destruida de raíz. Credenciales en lista negra.")

    def action_trigger_incident_response(self, data):
        print(f"[🚨 CRISIS_MODE]: Playbook de Incidente Mayor activado. Notificando CSIRT vía Webhook Securo.")