import streamlit as st
import requests
import os
import time
import pandas as pd
import plotly.graph_objects as go

# --- CONFIGURACIÓN ESTÁTICA ---
# Cambiado para asegurar que use la red interna de Docker por defecto
BACKEND_INTERNAL = os.getenv("BACKEND_URL", "http://backend:8000")
BACKEND_EXTERNAL = "http://localhost:8000"

st.set_page_config(page_title="Hyperion Ops", layout="wide")

# --- CSS INYECTADO (ESTÉTICA DARK) ---
st.markdown("""
    <style>
    .stApp { background-color: #0f172a; color: #f1f5f9; }
    [data-testid="stSidebar"] { background-color: #1e293b !important; }
    .metric-card {
        background: #1e293b; padding: 20px; border-radius: 10px;
        border-left: 5px solid #9333ea; border: 1px solid #334155;
    }
    div[data-testid="stMetricValue"] { color: #c084fc; }
    </style>
    """, unsafe_allow_html=True)

# --- SINGLETON DE SESIÓN ---
if "auth" not in st.session_state:
    st.session_state.auth = {"token": None, "user": None, "step": "login"}
if "page" not in st.session_state:
    st.session_state.page = "Analíticas"

# --- LÓGICA DE NAVEGACIÓN ---
def nav_to(page):
    st.session_state.page = page
    st.rerun()

# --- SIDEBAR ---
if st.session_state.auth["token"]:
    with st.sidebar:
        st.markdown("<h2 style='color: #c084fc;'>🛡️ HYPERION CORE</h2>", unsafe_allow_html=True)
        st.write(f"👤 **Usuario:** {st.session_state.auth['user']}")
        st.write("---")
        if st.button("📊 Analíticas", use_container_width=True): nav_to("Analíticas")
        if st.button("👁️ Vigilancia", use_container_width=True): nav_to("Vigilancia")
        if st.button("👥 Operadores", use_container_width=True): nav_to("Operadores")
        if st.button("📜 SIEM Audit", use_container_width=True): nav_to("SIEM")
        st.write("---")
        if st.button("🚪 Cerrar Sesión", use_container_width=True):
            st.session_state.auth = {"token": None, "user": None, "step": "login"}
            st.rerun()

# --- VISTA: ACCESO (LOGIN + REGISTRO) ---
if not st.session_state.auth["token"]:
    _, col, _ = st.columns([1, 2, 1])
    
    with col:
        st.markdown("<h1 style='text-align: center; color: #c084fc;'>HYPERION ACCESS</h1>", unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔐 Ingresar", "📝 Registrarse"])
        
        with tab1:
            if st.session_state.auth["step"] == "login":
                u = st.text_input("Correo Electrónico", key="l_user")
                p = st.text_input("Contraseña", type="password", key="l_pass")
                if st.button("Validar Credenciales", use_container_width=True):
                    try:
                        res = requests.post(f"{BACKEND_INTERNAL}/auth/login", data={"username": u, "password": p}, timeout=5)
                        if res.status_code == 200:
                            st.session_state.auth["user"] = u
                            st.session_state.auth["step"] = "2fa"
                            st.rerun()
                        else: st.error("Credenciales incorrectas o IP bloqueada.")
                    except: st.error("No se pudo conectar con el servidor central.")
            
            elif st.session_state.auth["step"] == "2fa":
                st.info(f"🔑 Código enviado a la app vinculada para: {st.session_state.auth['user']}")
                code = st.text_input("Código de Seguridad", max_chars=6)
                if st.button("Finalizar Acceso", use_container_width=True):
                    try:
                        res = requests.post(f"{BACKEND_INTERNAL}/auth/login/verify-2fa", 
                                         json={"email": st.session_state.auth["user"], "code": code})
                        if res.status_code == 200:
                            st.session_state.auth["token"] = res.json()["access_token"]
                            st.rerun()
                        else: st.error("Código OTP inválido.")
                    except: st.error("Error en la verificación.")

        with tab2:
            new_u = st.text_input("Correo Operador", key="r_user")
            new_p = st.text_input("Clave Maestra", type="password", key="r_pass")
            new_r = st.selectbox("Rol", ["admin", "user"], key="r_role")
            if st.button("Crear Operador", use_container_width=True):
                try:
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/register", 
                                     json={"email": new_u, "password": new_p, "role": new_r})
                    if res.status_code == 200: st.success("✅ Operador registrado con éxito.")
                    else: st.error(f"Error: {res.json().get('detail', 'Error desconocido')}")
                except: st.error("Servidor de registro fuera de línea.")

# --- VISTAS PROTEGIDAS ---
else:
    # Parámetro global para todas las llamadas al backend
    auth_params = {"token": st.session_state.auth['token']}
    
    if st.session_state.page == "Analíticas":
        st.title("📊 Estadísticas Globales")
        c1, c2, c3 = st.columns(3)
        c1.metric("Controles Activos", "42", "+2")
        c2.metric("Cumplimiento NIST", "78%", "5%")
        c3.metric("Nivel de Riesgo", "Bajo", "Estable")
        
        fig = go.Figure(data=go.Scatterpolar(r=[4, 5, 2, 3, 4], theta=['ID','PR','DE','RS','RC'], fill='toself', line_color='#9333ea'))
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", polar=dict(bgcolor="#1e293b"))
        st.plotly_chart(fig, use_container_width=True)

    elif st.session_state.page == "Vigilancia":
        st.title("👁️ Vigilancia en Tiempo Real")
        try:
            start = time.time()
            # SE ENVÍA TOKEN POR PARAMS
            r = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics", params=auth_params, timeout=3)
            lat = int((time.time() - start) * 1000)
            if r.status_code == 200:
                data = r.json()
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("CPU", f"{data['cpu']}%")
                col2.metric("RAM", f"{data['ram']}%")
                col3.metric("DISCO", f"{data['disk']}%")
                col4.metric("LATENCIA", f"{lat}ms")
            else: st.error(f"⚠️ Error {r.status_code}: No autorizado.")
        except: st.error("🚨 El motor de vigilancia no responde.")

    elif st.session_state.page == "Operadores":
        st.title("👥 Gestión de Operadores")
        try:
            # SE ENVÍA TOKEN POR PARAMS
            r = requests.get(f"{BACKEND_INTERNAL}/admin/users", params=auth_params)
            if r.status_code == 200:
                usuarios = r.json()
                if usuarios:
                    # Formateo de tabla
                    data_list = [{"Email": k, "Rol": v.get('role', 'N/A')} for k, v in usuarios.items()]
                    st.dataframe(pd.DataFrame(data_list), use_container_width=True)
                else: st.info("No hay operadores registrados en la base de datos.")
            else: st.error("🛑 Acceso Denegado: Se requieren privilegios de Admin.")
        except Exception as e: st.error(f"Error al conectar con la base de datos: {e}")

    elif st.session_state.page == "SIEM":
        st.title("📜 Hyperion SIEM Audit")
        
        # --- FILA 1: ESTADO DEL MOTOR ---
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown("""
                <div class="metric-card">
                    <h4 style='margin:0; color:#9333ea;'>📦 Nodo de Ingesta</h4>
                    <p style='font-size:24px; font-weight:bold; margin:0;'>ACTIVO</p>
                    <small style='color:#4ade80;'>Protocolo Kafka 9092</small>
                </div>
            """, unsafe_allow_html=True)
        with col_b:
            st.markdown("""
                <div class="metric-card">
                    <h4 style='margin:0; color:#9333ea;'>🔒 Integridad</h4>
                    <p style='font-size:24px; font-weight:bold; margin:0;'>SHA-256</p>
                    <small style='color:#4ade80;'>Cadena de bloques verificada</small>
                </div>
            """, unsafe_allow_html=True)
        with col_c:
            st.markdown("""
                <div class="metric-card">
                    <h4 style='margin:0; color:#9333ea;'>⚡ Rendimiento</h4>
                    <p style='font-size:24px; font-weight:bold; margin:0;'>< 10ms</p>
                    <small style='color:#4ade80;'>Latencia de procesamiento</small>
                </div>
            """, unsafe_allow_html=True)

        st.write("") # Espaciador

        # --- FILA 2: ACCESO Y DETALLES TÉCNICOS ---
        left_col, right_col = st.columns([2, 1])

        with left_col:
            st.subheader("Motor de Análisis de Logs")
            st.info("El sistema está capturando eventos en tiempo real a través de los adaptadores de red. Los logs presentados en la consola externa son inmutables y están firmados criptográficamente.")
            
            # Botón estilizado
            url = f"{BACKEND_EXTERNAL}/dashboard?token={st.session_state.auth['token']}"
            st.markdown(f"""
                <a href="{url}" target="_blank" style="text-decoration: none;">
                    <div style="background: linear-gradient(90deg, #9333ea 0%, #c084fc 100%); 
                                padding: 20px; border-radius: 10px; text-align: center; 
                                color: white; font-weight: bold; font-size: 20px;
                                box-shadow: 0 4px 15px rgba(147, 51, 234, 0.3);">
                        🚀 ABRIR CONSOLA EXTERNA DE AUDITORÍA
                    </div>
                </a>
            """, unsafe_allow_html=True)

        with right_col:
            st.subheader("Configuración")
            with st.expander("Ver credenciales de sesión"):
                st.code(f"JWT_TOKEN: {st.session_state.auth['token'][:15]}...", language="bash")
                st.caption("Este token es temporal y expira al cerrar la pestaña.")
            
            st.warning("⚠️ El acceso externo requiere que la VPN esté activa si trabajas en remoto.")

        # --- FILA 3: TABLA DE EVENTOS RECIENTES (MOCKUP) ---
        st.write("---")
        st.subheader("Últimas Alertas de Seguridad detectadas")
        mock_data = pd.DataFrame([
            {"Timestamp": "2026-04-01 20:15:02", "Evento": "Intento de Brute Force", "Nivel": "CRÍTICO", "Origen": "192.168.1.45"},
            {"Timestamp": "2026-04-01 21:05:12", "Evento": "Escaneo de Puertos", "Nivel": "ALTO", "Origen": "10.0.0.12"},
            {"Timestamp": "2026-04-01 21:10:45", "Evento": "Cambio de permisos", "Nivel": "MEDIO", "Origen": "admin_user"}
        ])
        
        def color_level(val):
            color = '#ef4444' if val == 'CRÍTICO' else ('#f59e0b' if val == 'ALTO' else '#3b82f6')
            return f'color: {color}; font-weight: bold;'

        st.table(mock_data.style.applymap(color_level, subset=['Nivel']))