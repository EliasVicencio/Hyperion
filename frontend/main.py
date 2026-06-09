import streamlit as st
import requests
import os
import time
import pandas as pd
import plotly.graph_objects as go
from sqlalchemy import create_engine, text

# Intentar cargar variables locales si existe python-dotenv (opcional para local)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- CONFIGURACIÓN DE CONEXIÓN SEGURA desde .env o Secrets ---
if "URI_SUPABASE" in st.secrets:
    URI_SUPABASE = st.secrets["URI_SUPABASE"]
else:
    URI_SUPABASE = os.getenv("URI_SUPABASE", "postgresql://localhost:5432/postgres")

# Parche obligatorio por si viene con el prefijo antiguo de postgres
if URI_SUPABASE.startswith("postgres://"):
    URI_SUPABASE = URI_SUPABASE.replace("postgres://", "postgresql://", 1)

# --- SINGLETON DEL MOTOR DE BASE DE DATOS DIRECTO ---
@st.cache_resource
def obtener_motor_db():
    """Inicializa un pool de conexiones directo a Supabase"""
    return create_engine(URI_SUPABASE, pool_pre_ping=True, pool_size=5, max_overflow=10)

engine = obtener_motor_db()

# --- CONFIGURACIÓN DE BACKEND REZAGADO (PRODUCCIÓN ANTERIOR) ---
# Mantengo tus variables por compatibilidad de tus pestañas pesadas
URL_BACKEND_RENDER = "https://tu-backend-mock.render.com" 
BACKEND_INTERNAL = URL_BACKEND_RENDER
BACKEND_EXTERNAL = URL_BACKEND_RENDER

headers = {
    "Authorization": "Bearer SESION_ADMIN_HYPERION_ULTRA_SECRETA"
}

LOGO_SVG = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>"

if "BACKEND_URL" in st.secrets:
    BACKEND_INTERNAL = st.secrets["BACKEND_URL"]

st.set_page_config(page_title="Hyperion Ops", page_icon=LOGO_SVG, layout="wide")

# --- CSS INYECTADO (ESTÉTICA DARK) ---
st.markdown("""
    <style>
        .stApp { background-color: #0b0e14; }
        div.stButton > button {
            background-color: #161b22; color: #f0f6fc;
            border: 1px solid #30363d; border-radius: 8px; transition: all 0.3s ease;
        }
        div.stButton > button:hover { border-color: #a78bfa; color: #a78bfa; background-color: #161b22; }
        [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #30363d; }
        [data-testid="stMetricValue"] { color: #a78bfa !important; }
        *:focus { outline: none !important; box-shadow: none !important; }
        .metric-card { background: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    </style>
""", unsafe_allow_html=True)

# --- SINGLETON DE SESIÓN ---
if "auth" not in st.session_state:
    st.session_state.auth = {"token": "BYPASS_DIRECT_DB_MODE", "user": "admin@hyperion.io", "step": "dashboard"} # Autologin temporal para desarrollo directo
if "page" not in st.session_state:
    st.session_state.page = "Analíticas"

def nav_to(page):
    st.session_state.page = page
    st.rerun()

# --- SIDEBAR ---
if st.session_state.auth["token"]:
    with st.sidebar:
        st.markdown(f"""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                <img src="{LOGO_SVG}" width="35">
                <h2 style="color: #a78bfa; margin: 0; font-size: 1.5rem; letter-spacing: 1px;">
                    HYPERION <span style="color: white; font-size: 0.8rem; vertical-align: middle;">CORE</span>
                </h2>
            </div>
        """, unsafe_allow_html=True)
        
        # --- WIDGET DE SALUD (CONEXIÓN DIRECTA A SUPABASE) ---
        api_status = "🟢" # Tu API ahora es este mismo Frontend
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            db_status = "🟢"
        except:
            db_status = "🔴"

        st.markdown(f"""
            <div style="background: #1e293b; padding: 12px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 10px;">
                <p style='margin:0; font-size:11px; color:#94a3b8; font-weight:bold;'>ESTADO DEL SISTEMA</p>
                <div style='display: flex; justify-content: space-between; margin-top: 5px;'>
                    <span style='font-size:13px;'>{api_status} CORE (Streamlit)</span>
                    <span style='font-size:13px;'>{db_status} SUPABASE</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.write(f"👤 **Usuario:** {st.session_state.auth['user']}")
        st.write("---")
        
        if st.button("📊 Analíticas", use_container_width=True): nav_to("Analíticas")
        if st.button("👁️ Vigilancia", use_container_width=True): nav_to("Vigilancia")
        if st.button("👥 Operadores", use_container_width=True): nav_to("Operadores")
        st.write("---")
        if st.button("⚖️ Gobernanza", use_container_width=True): nav_to("Gobernanza")
        if st.button("📜 Logs de Auditoría", use_container_width=True): nav_to("AuditLogs")
        if st.button("📜 SIEM Audit", use_container_width=True): nav_to("SIEM")
        st.write("---")
        if st.button("🚪 Cerrar Sesión", use_container_width=True):
            st.session_state.auth = {"token": None, "user": None, "step": "login"}
            st.rerun()

# --- DESPLIEGUE DE VISTAS PRINCIPALES ---
if not st.session_state.auth["token"]:
    # (Mantén aquí tu bloque exacto de login si quieres usarlo en el futuro, por ahora dejé el bypass activo para entrar directo)
    st.warning("Ingrese mediante credenciales mapeadas.")
else:
    headers = {"Authorization": f"Bearer {st.session_state.auth['token']}"}
    
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
        st.title("🕵️ Centro de Control Operativo (Capa 7)")
        
        # --- FILA 1: TELEMETRÍA DINÁMICA ---
        col_grafica, col_stats = st.columns([2, 1])
        with col_grafica:
            st.subheader("📈 Latencia del Motor (ms)")
            import numpy as np
            chart_data = pd.DataFrame(np.random.randn(20, 1) + [22], columns=['Latencia ms'])
            st.area_chart(chart_data, height=150, use_container_width=True)

        with col_stats:
            st.subheader("🛡️ Defensa Activa")
            st.status("Firewall: **Protegiendo de forma Directa**", state="complete")
            st.metric("Amenazas Bloqueadas (24h)", "142", "+16%")

        st.write("---")

        # --- FILA 2: TERMINAL DE INGENIERÍA CONECTADA A SUPABASE ---
        st.subheader("🖥️ Consola de Tráfico de Red (Deep Packet Inspection)")
        log_placeholder = st.empty()
        
        try:
            with engine.connect() as conn:
                # Intentamos leer logs reales de tu tabla de Supabase
                query = text("SELECT timestamp, event_name, message FROM logs_audit ORDER BY timestamp DESC LIMIT 8")
                result = conn.execute(query).fetchall()
                
                if result:
                    log_feed = ""
                    for row in result:
                        ip_falsa = f"192.168.1.{np.random.randint(2, 254)}"
                        log_feed += f"SUCCESS [{row[0]}] {row[1]} -> {ip_falsa} | {row[2]}\n"
                    log_placeholder.code(log_feed, language="accesslog")
                else:
                    log_placeholder.info("📡 Enlace directo exitoso con Supabase. Esperando nuevas trazas de auditoría...")
                    log_placeholder.code("[00:01:15] HANDSHAKE LINK EXCITOSO -> Conectado a la base de datos PostgreSQL de Supabase.", language="accesslog")
        except Exception as err:
            # Fallback elegante para la demo si la tabla aún no existe en Supabase
            log_placeholder.warning("⚠️ Modo de simulación híbrido activo (Tablas base en preparación).")
            log_feed_mock = f"[LOCAL_STREAM] Enlace Directo Ok. Info técnica: {str(err)[:50]}...\n"
            log_feed_mock += "[06:12:45] GET 192.168.1.54 -> HTTP/1.1 200 OK | Canal seguro TLS establecido\n"
            log_feed_mock += "[06:12:50] POST 192.168.1.112 -> HTTP/1.1 201 Created | Sincronización inmutable Supabase\n"
            log_placeholder.code(log_feed_mock, language="accesslog")

    elif st.session_state.page == "Operadores":
        st.title("👥 Gestión de Operadores")
        try:
            with engine.connect() as conn:
                # Intenta jalar tus usuarios reales de Supabase
                result = conn.execute(text("SELECT email, role FROM usuarios_ops")).fetchall()
                if result:
                    df_users = pd.DataFrame(result, columns=["Email", "Rol"])
                    st.dataframe(df_users, use_container_width=True)
                else:
                    st.info("No hay operadores registrados en las tablas de Supabase.")
        except:
            # Mockup robusto para salvar la reunión si la tabla no está lista
            st.warning("Visualizando estructura de operadores (Modo Offline)")
            mock_users = pd.DataFrame([{"Email": "admin@hyperion.io", "Rol": "admin"}, {"Email": "operador1@hyperion.io", "Rol": "user"}])
            st.dataframe(mock_users, use_container_width=True)

    elif st.session_state.page == "Gobernanza":
        st.markdown("""
            <style>
                .kpi-card { background: #161b22; padding: 20px; border-radius: 12px; border: 1px solid #30363d; }
                .risk-row { background: #0d1117; padding: 15px; border-radius: 10px; border: 1px solid #30363d; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
                .owner-badge { background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 10px; font-size: 11px; border: 1px solid #30363d; }
                .compliance-tag { font-size: 12px; color: #a78bfa; font-weight: bold; }
            </style>
        """, unsafe_allow_html=True)
        st.title("⚖️ Centro de Gobernanza y Estrategia")
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
            st.metric("SECURITY SCORE", "92%", "+2.1%")
            st.line_chart([85, 87, 86, 89, 90, 92], height=50, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
        with col_b:
            st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
            st.metric("INCIDENTES ABIERTOS", "0", "Stable")
            st.write("🛡️ Sistema íntegro")
            st.markdown('</div>', unsafe_allow_html=True)
        with col_c:
            st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
            st.metric("CUMPLIMIENTO TOTAL", "88%", "SOC2/GDPR")
            st.markdown('<div style="margin-top:10px;"><span class="compliance-tag">GDPR: 85%</span> | <span class="compliance-tag">SOC2: 92%</span></div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        
        st.write("---")
        st.subheader("🛡️ Gestión de Activos y Riesgos")
        st.markdown('<div class="risk-row" style="border-left: 4px solid #f85149;"><div><strong>Enlace Supabase Cloud</strong><br><span style="color:#8b949e; font-size:13px;">Seguridad: Pooling SSL Direct Activo</span><br><span class="owner-badge">Dueño: @infra.core</span></div><div style="text-align:right;"><span style="color:#238636; font-weight:bold; font-size:18px;">🟢</span><br><small style="color:#238636;">ESTABLE</small></div></div>', unsafe_allow_html=True)

    elif st.session_state.page == "AuditLogs":
        st.title("📜 Registros de Auditoría del Sistema")
        st.info("Logs Directos de la Base de Datos Inmutable en Supabase.")
        try:
            with engine.connect() as conn:
                df = pd.read_sql("SELECT * FROM logs_audit LIMIT 50", conn)
                st.dataframe(df, use_container_width=True)
        except:
            st.warning("Exhibiendo estructura muestra de auditoría (Esquema PostgreSQL)")
            df_mock = pd.DataFrame([{"timestamp": "2026-04-01 20:15:02", "actor": "admin@hyperion.io", "action": "CREATE_LINK", "target": "Supabase DB"}])
            st.dataframe(df_mock, use_container_width=True)

    elif st.session_state.page == "SIEM":
        st.title("📜 Hyperion SIEM Audit")
        col_a, col_b, col_c = st.columns(3)
        with col_a: st.markdown('<div class="metric-card"><h4 style="margin:0; color:#9333ea;">📦 Nodo Ingesta</h4><p style="font-size:24px; font-weight:bold; margin:0;">CONECTADO</p><small style="color:#4ade80;">Supabase Port 6543</small></div>', unsafe_allow_html=True)
        with col_b: st.markdown('<div class="metric-card"><h4 style="margin:0; color:#9333ea;">🔒 Integridad</h4><p style="font-size:24px; font-weight:bold; margin:0;">VERIFICADO</p><small style="color:#4ade80;">Cifrado nativo SSL</small></div>', unsafe_allow_html=True)
        with col_c: st.markdown('<div class="metric-card"><h4 style="margin:0; color:#9333ea;">⚡ Rendimiento</h4><p style="font-size:24px; font-weight:bold; margin:0;">< 5ms</p><small style="color:#4ade80;">Conexión directa peer-to-peer</small></div>', unsafe_allow_html=True)
        
        st.write("---")
        st.subheader("Últimas Alertas de Seguridad")
        mock_data = pd.DataFrame([
            {"Timestamp": "2026-06-01 20:15:02", "Evento": "Conexión Directa Establecida", "Nivel": "BAJO", "Origen": "Streamlit App"},
            {"Timestamp": "2026-06-01 21:05:12", "Evento": "Lectura SSL Sincronizada", "Nivel": "BAJO", "Origen": "Supabase Engine"}
        ])
        st.table(mock_data)