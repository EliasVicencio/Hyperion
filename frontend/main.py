import streamlit as st
import requests
import os
import time
import pandas as pd

# --- CONFIGURACIÓN DE RED ---
BACKEND_INTERNAL = os.getenv("BACKEND_URL", "http://backend:8000")
BACKEND_EXTERNAL = "http://localhost:8000"
TOTP_SECRET = "JBSWY3DPEHPK3PXP" 

st.set_page_config(page_title="Hyperion Ops", layout="wide", page_icon="🛡️")

# --- INICIALIZACIÓN DE ESTADOS ---
if "token" not in st.session_state: st.session_state.token = None
if "requires_2fa" not in st.session_state: st.session_state.requires_2fa = False
if "temp_email" not in st.session_state: st.session_state.temp_email = ""
if "role" not in st.session_state: st.session_state.role = "empleado"
if "metrics_history" not in st.session_state: st.session_state.metrics_history = {"cpu": [], "ram": []}

# --- SIDEBAR ---
st.sidebar.title("🛡️ Hyperion System")
if st.session_state.token:
    menu = ["Acceso", "Central de Vigilancia", "Configurar 2FA", "Dashboard de Auditoría"]
    # Filtrar menú para no admins
    if st.session_state.role != "admin":
        menu = [m for m in menu if m not in ["Configurar 2FA", "Dashboard de Auditoría"]]
else:
    menu = ["Acceso"]

choice = st.sidebar.selectbox("Navegación", menu)

# --- VISTA: ACCESO (CON QR 2FA) ---
if choice == "Acceso":
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center;'>🔐 Control de Acceso</h1>", unsafe_allow_html=True)
        
        if st.session_state.requires_2fa:
            st.warning("Verificación de Dos Pasos Requerida")
            # --- SECCIÓN QR REINTEGRADA ---
            with st.expander("📱 Vincular App de Seguridad (Google Authenticator)", expanded=True):
                qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=otpauth://totp/Hyperion:{st.session_state.temp_email}?secret={TOTP_SECRET}&issuer=Hyperion"
                st.image(qr_url, caption="Escanea este código con tu móvil")
                st.code(f"Manual Key: {TOTP_SECRET}", language="text")
            
            otp = st.text_input("Ingresa el código de 6 dígitos", max_chars=6)
            if st.button("Verificar y Entrar", use_container_width=True):
                try:
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/login/verify-2fa", 
                                     json={"email": st.session_state.temp_email, "code": otp})
                    if res.status_code == 200:
                        datos = res.json()
                        st.session_state.token = datos["access_token"]
                        st.session_state.role = datos.get("role", "admin")
                        st.session_state.requires_2fa = False
                        st.success(f"Bienvenido, Operador. Nivel: {st.session_state.role.upper()}")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Código OTP inválido")
                except:
                    st.error("Error: Backend no responde")

        elif not st.session_state.token:
            user = st.text_input("Usuario / Email")
            password = st.text_input("Contraseña", type="password")
            if st.button("Iniciar Protocolo de Ingreso", use_container_width=True):
                try:
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/login", data={"username": user, "password": password})
                    if res.status_code == 200:
                        st.session_state.requires_2fa = True
                        st.session_state.temp_email = user
                        st.rerun()
                    else:
                        st.error("Credenciales Inválidas")
                except:
                    st.error("Servidor Backend Offline")
        else:
            st.balloons()
            st.info(f"Sesión activa: {st.session_state.temp_email}")
            if st.button("Terminar Sesión Segura", use_container_width=True):
                st.session_state.token = None
                st.rerun()

# --- VISTA: CONFIGURAR 2FA (ADMIN) ---
elif choice == "Configurar 2FA":
    st.title("🔐 Gestión de Protocolos 2FA")
    st.info(f"**Secreto Maestro Global:** `{TOTP_SECRET}`")
    st.write("Cualquier operador nuevo deberá usar este secreto para vincular su aplicación.")
    if st.button("Generar Nuevo Secreto (Simulado)"):
        st.warning("Esta acción invalidaría todos los accesos actuales.")

# --- VISTA: CENTRAL DE VIGILANCIA (CON GRÁFICOS) ---
elif choice == "Central de Vigilancia":
    st.title("👁️ Vigilancia de Infraestructura")
    
    # Contenedores para métricas
    m1, m2, m3 = st.columns(3)
    cpu_p = m1.empty()
    ram_p = m2.empty()
    dsk_p = m3.empty()
    
    chart_p = st.empty()
    
    # Bucle de actualización en tiempo real
    for _ in range(20): # Actualiza 20 veces
        try:
            res = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics", params={"token": st.session_state.token})
            if res.status_code == 200:
                data = res.json()
                
                # Actualizar métricas visuales
                cpu_p.metric("Carga CPU", f"{data['cpu']}%")
                ram_p.metric("Uso RAM", f"{data['ram']}%")
                dsk_p.metric("Espacio Disco", f"{data['disk']}%")
                
                # Actualizar Historial para el gráfico
                st.session_state.metrics_history["cpu"].append(data['cpu'])
                st.session_state.metrics_history["ram"].append(data['ram'])
                
                # Limitar historial a 20 puntos
                if len(st.session_state.metrics_history["cpu"]) > 20:
                    st.session_state.metrics_history["cpu"].pop(0)
                    st.session_state.metrics_history["ram"].pop(0)
                
                # Dibujar gráfico
                chart_p.line_chart(st.session_state.metrics_history)
                
                time.sleep(2)
            else:
                st.error("Pérdida de señal con el Backend")
                break
        except:
            break

# --- VISTA: DASHBOARD DE AUDITORÍA (COMPLETO) ---
elif choice == "Dashboard de Auditoría":
    st.title("📜 Centro de Control y Auditoría Hyperion")
    
    if st.session_state.role != "admin":
        st.error("🚫 Acceso restringido a personal de seguridad nivel 3.")
    else:
        # Definimos las 3 pestañas solicitadas
        tab_siem, tab_users, tab_engine = st.tabs([
            "🔍 Bóvedas SIEM", 
            "👥 Usuarios Registrados", 
            "⚙️ Motor de Ingesta"
        ])

        # PESTAÑA 1: Bóvedas SIEM (Logs Externos)
        with tab_siem:
            st.subheader("Análisis de Bóvedas Inmutables")
            fuente = st.selectbox("Seleccionar Bóveda", ["finance_service", "hr_service"])
            
            url_siem = f"{BACKEND_INTERNAL}/api/v1/ingest/logs/{fuente}?token={st.session_state.token}"
            res_siem = requests.get(url_siem)
            
            if res_siem.status_code == 200:
                logs = res_siem.json()
                if logs:
                    if st.button(f"Validar Integridad: {fuente}"):
                        is_valid = all(logs[i]["hash_prev"] == logs[i-1]["hash_this"] for i in range(1, len(logs)))
                        if is_valid: st.success("✅ Cadena de custodia verificada.")
                        else: st.error("🚨 ALERTA: Alteración de datos detectada.")
                    st.dataframe(pd.DataFrame(logs), use_container_width=True)
                else:
                    st.info("Bóveda vacía.")
            else:
                st.error("Error al conectar con la bóveda SIEM.")

        # PESTAÑA 2: Usuarios Registrados
        with tab_users:
            st.subheader("Gestión de Operadores Autorizados")
            # Este endpoint debe existir en tu backend (main.py)
            url_users = f"{BACKEND_INTERNAL}/admin/users?token={st.session_state.token}"
            try:
                res_u = requests.get(url_users)
                if res_u.status_code == 200:
                    usuarios = res_u.json()
                    if usuarios:
                        # Convertimos el diccionario de usuarios a una lista para el DataFrame
                        user_list = [{"Email": k, "Rol": v["role"]} for k, v in usuarios.items()]
                        st.table(user_list)
                    else:
                        st.warning("No hay usuarios registrados.")
                else:
                    st.error("No se pudo obtener la lista de usuarios (Endpoint no disponible).")
            except:
                st.error("Fallo de conexión con el módulo de usuarios.")

        # PESTAÑA 3: Motor de Ingesta (Acceso al Dashboard HTML)
        with tab_engine:
            st.subheader("⚙️ Infraestructura y Panel Externo")
            st.info("Desde aquí puedes acceder al dashboard nativo del backend para ver métricas de bajo nivel.")
            
            # URL para el dashboard HTML del backend
            url_html = f"{BACKEND_EXTERNAL}/dashboard?token={st.session_state.token}"
            
            st.markdown(f"""
                <div style="background-color:#1e1e1e; padding:20px; border-radius:10px; border: 1px solid #333; text-align:center;">
                    <p>Acceso Seguro vía Túnel Hyperion</p>
                    <a href="{url_html}" target="_blank" style="text-decoration:none;">
                        <button style="background-color:#ff4b4b; color:white; border:none; padding:10px 20px; border-radius:5px; cursor:pointer; font-weight:bold;">
                            🚀 ABRIR PANEL HTML EXTERNO
                        </button>
                    </a>
                </div>
            """, unsafe_allow_html=True)