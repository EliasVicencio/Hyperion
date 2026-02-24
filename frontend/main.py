import streamlit as st
import requests
import os
import time
import pandas as pd

# --- CONFIGURACIÓN DE RED ---
# 'backend' es el nombre del servicio en docker-compose
BACKEND_INTERNAL = os.getenv("BACKEND_URL", "http://backend:8000")
BACKEND_EXTERNAL = "http://localhost:8000"
TOTP_SECRET = "JBSWY3DPEHPK3PXP" 

st.set_page_config(page_title="Hyperion Ops", layout="wide")

# --- INICIALIZACIÓN DE ESTADOS ---
if "token" not in st.session_state: st.session_state.token = None
if "requires_2fa" not in st.session_state: st.session_state.requires_2fa = False
if "temp_email" not in st.session_state: st.session_state.temp_email = ""
if "role" not in st.session_state: st.session_state.role = "empleado"

# --- SIDEBAR / NAVEGACIÓN ---
st.sidebar.title("🛡️ Hyperion System")

# Definición de menú según rol y estado de autenticación
if st.session_state.token:
    menu = ["Acceso", "Central de Vigilancia"]
    if st.session_state.role == "admin":
        menu.insert(1, "Configurar 2FA")
        menu.insert(2, "Dashboard de Auditoría")
else:
    menu = ["Acceso"]

choice = st.sidebar.selectbox("Navegación", menu)

# --- VISTA: ACCESO (LOGIN Y REGISTRO) ---
if choice == "Acceso":
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center;'>🔐 Control de Acceso</h1>", unsafe_allow_html=True)
        
        # PASO 2: Verificación 2FA
        if st.session_state.requires_2fa:
            st.warning("Verificación de Dos Pasos Requerida")
            with st.expander("📱 Vincular App de Seguridad", expanded=True):
                qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=otpauth://totp/Hyperion:{st.session_state.temp_email}?secret={TOTP_SECRET}&issuer=Hyperion"
                st.image(qr_url)
                st.code(f"Código Secreto: {TOTP_SECRET}", language="text")
            
            otp = st.text_input("Ingresa el código de tu App", max_chars=6)
            if st.button("Verificar y Entrar", use_container_width=True):
                try:
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/login/verify-2fa", 
                                     json={"email": st.session_state.temp_email, "code": otp})
                    if res.status_code == 200:
                        datos = res.json()
                        st.session_state.token = datos["access_token"]
                        st.session_state.role = datos.get("role", "empleado")
                        st.session_state.requires_2fa = False
                        st.success(f"Bienvenido. Nivel de acceso: {st.session_state.role.upper()}")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Código OTP incorrecto")
                except:
                    st.error("Error de conexión con el backend")

        # PASO 1: Login o Registro
        elif not st.session_state.token:
            tab_login, tab_reg = st.tabs(["Iniciar Sesión", "Registrar Operador"])
            
            with tab_login:
                user = st.text_input("Usuario / Email")
                password = st.text_input("Contraseña", type="password")
                if st.button("Ingresar al Sistema", use_container_width=True):
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/login", data={"username": user, "password": password})
                    if res.status_code == 200:
                        st.session_state.requires_2fa = True
                        st.session_state.temp_email = user
                        st.rerun()
                    else:
                        st.error("Credenciales incorrectas o IP bloqueada")
            
            with tab_reg:
                new_user = st.text_input("Nuevo Usuario")
                new_pass = st.text_input("Nueva Clave", type="password")
                rol_sel = st.selectbox("Nivel de Acceso", ["admin", "empleado"])
                if st.button("Crear Cuenta", use_container_width=True):
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/register", 
                                     json={"email": new_user, "password": new_pass, "role": rol_sel})
                    if res.status_code == 200:
                        st.success(f"Operador {rol_sel} registrado")
                    else:
                        st.error("Error al registrar")
        
        else:
            st.balloons()
            st.info(f"Sesión activa: {st.session_state.temp_email} | Rol: {st.session_state.role.upper()}")
            if st.button("Cerrar Sesión Segura", use_container_width=True):
                st.session_state.token = None
                st.session_state.role = "empleado"
                st.rerun()

# --- VISTA: CONFIGURAR 2FA (SOLO ADMIN) ---
elif choice == "Configurar 2FA":
    st.title("🔐 Gestión de Protocolos 2FA")
    if st.session_state.role != "admin":
        st.error("🚫 Acceso denegado.")
    else:
        st.info(f"**Secreto Maestro Actual:** `{TOTP_SECRET}`")
        user_to_reset = st.text_input("Correo del operador a resetear")
        if st.button("Habilitar Nueva Vinculación"):
            st.success(f"Acceso para {user_to_reset} reiniciado (Simulado)")

# --- VISTA: DASHBOARD DE AUDITORÍA (SOLO ADMIN) ---
elif choice == "Dashboard de Auditoría":
    st.title("📜 Centro de Control y Auditoría")
    if st.session_state.role != "admin":
        st.error("🚫 Acceso denegado.")
    else:
        tab_audit, tab_users, tab_engine = st.tabs(["📜 Historial Inmutable", "👥 Usuarios", "⚙️ Motor"])
        
        with tab_audit:
            res = requests.get(f"{BACKEND_INTERNAL}/admin/audit", params={"token": st.session_state.token})
            if res.status_code == 200:
                logs = res.json()
                if logs:
                    # Verificación de integridad simple
                    is_valid = True
                    for i in range(1, len(logs)):
                        if logs[i]["hash_prev"] != logs[i-1]["hash_this"]:
                            is_valid = False
                    
                    if is_valid: st.success(f"✅ INTEGRIDAD GARANTIZADA ({len(logs)} bloques)")
                    else: st.error("🚨 ALERTA: Cadena de custodia alterada")
                    
                    df = pd.DataFrame(logs)
                    st.dataframe(df[['timestamp', 'actor', 'action', 'hash_this']], use_container_width=True)
                else:
                    st.info("Sin registros de auditoría.")
            else:
                st.error("Error al obtener logs.")

        with tab_users:
            res = requests.get(f"{BACKEND_INTERNAL}/admin/users", params={"token": st.session_state.token})
            if res.status_code == 200:
                st.dataframe(res.json(), use_container_width=True)

        with tab_engine:
            st.subheader("⚙️ Infraestructura de Control")
            st.info("Este acceso directo abre el Panel de Control Hyperion en una nueva instancia segura.")
            
            # Definimos la URL
            url = f"{BACKEND_EXTERNAL}/dashboard?token={st.session_state.token}"
            
            # Botón con estilo mejorado
            st.markdown(f"""
                <a href="{url}" target="_blank" style="text-decoration: none;">
                    <div style="
                        background-color: #262730;
                        color: #ffffff;
                        padding: 15px;
                        text-align: center;
                        border-radius: 10px;
                        border: 1px solid #464b5d;
                        font-weight: bold;
                        transition: 0.3s;
                        cursor: pointer;
                        margin-top: 10px;">
                        🚀 ABRIR PANEL DE CONTROL EXTERNO
                    </div>
                </a>
                <p style="text-align: center; font-size: 0.8em; color: #808495; margin-top: 10px;">
                    Protocolo de túnel activo: {BACKEND_EXTERNAL}
                </p>
            """, unsafe_allow_html=True)

# --- VISTA: CENTRAL DE VIGILANCIA (TODOS LOS LOGUEADOS) ---
elif choice == "Central de Vigilancia":
    st.title("👁️ Central de Vigilancia")
    if not st.session_state.token:
        st.error("Acceso restringido.")
    else:
        col_m1, col_m2, col_m3 = st.columns(3)
        cpu_stat = col_m1.empty()
        ram_stat = col_m2.empty()
        disk_stat = col_m3.empty()
        
        if "metrics_history" not in st.session_state:
            st.session_state.metrics_history = {"cpu": [], "ram": []}

        # Bucle de actualización (10 ciclos)
        for _ in range(10):
            try:
                res = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics", params={"token": st.session_state.token})
                if res.status_code == 200:
                    data = res.json()
                    cpu_stat.metric("CPU", f"{data['cpu']}%")
                    ram_stat.metric("RAM", f"{data['ram']}%")
                    disk_stat.metric("Disco", f"{data['disk']}%")
                    
                    st.session_state.metrics_history["cpu"].append(data['cpu'])
                    st.session_state.metrics_history["ram"].append(data['ram'])
                    # Mantener solo los últimos 20 datos
                    if len(st.session_state.metrics_history["cpu"]) > 20:
                        st.session_state.metrics_history["cpu"].pop(0)
                        st.session_state.metrics_history["ram"].pop(0)
                    
                    st.line_chart(st.session_state.metrics_history)
                time.sleep(2)
            except:
                st.error("Error obteniendo métricas")
                break