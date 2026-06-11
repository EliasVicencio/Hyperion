from security.soar_core import execute_autonomous_playbook

print("🚀 Iniciando Simulación de Validación - Semana 4: Gestión de Falsos Positivos")
print("===============================================================================")

# 1. Este evento simula un backup pesado nocturno que suele confundirse con exfiltración de datos
print("\n[Escenario 1] Servidor Interno de Backups Protegido realiza sincronización masiva...")
execute_autonomous_playbook(
    severity="high", 
    source_ip="192.168.1.50", 
    threat_detail="Tráfico saliente inusualmente alto (Falsa Alarma de Exfiltración)"
)

# 2. Este evento simula a un atacante real intentando vulnerar la plataforma
print("\n[Escenario 2] IP externa no registrada intenta fuerza bruta contra paneles expuestos...")
execute_autonomous_playbook(
    severity="critical", 
    source_ip="45.66.21.112", 
    user_email="adversary_ext@blackhat.org", 
    threat_detail="Fuerza Bruta SSH detectada por Darktrace"
)

print("\n===============================================================================")
print("✅ Simulación concluida. Revisa el comportamiento en la terminal y actualiza tu base de datos.")