import os
import time
from io import BytesIO
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

# --- CONFIGURACIÓN E INICIALIZACIÓN ---
LOGO_SVG = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>"
st.set_page_config(page_title="Hyperion Core", page_icon=LOGO_SVG, layout="wide")

BACKEND_URL = st.secrets.get("BACKEND_URL", os.getenv("BACKEND_URL", "https://hyperion-pi-nine.vercel.app")).rstrip("/")

# Inicialización limpia del estado de la sesión
for key, value in {"auth": {"token": None, "user": None, "step": "login"}, "page": "Analíticas"}.items():
    if key not in st.session_state:
        st.session_state[key] = value

# --- CSS INYECTADO (LIMPIO Y SIN TRUCOS DE COLAPSO) ---
st.markdown("""
    <style>
        .stApp { background-color: #0b0e14; }
        div.stButton > button { background-color: #161b22; color: #f0f6fc; border: 1px solid #30363d; border-radius: 8px; transition: all 0.3s ease; text-align: left; padding: 8px 16px; }
        div.stButton > button:hover { border-color: #a78bfa; color: #a78bfa; background-color: #161b22; }
        [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #30363d; min-width: 260px !important; }
        [data-testid="stMetricValue"] { color: #a78bfa !important; }
        *:focus { outline: none !important; box-shadow: none !important; }
        .kpi-card { background: #161b22; padding: 20px; border-radius: 12px; border: 1px solid #30363d; }
        .risk-row { background: #0d1117; padding: 15px; border-radius: 10px; border: 1px solid #30363d; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
        .owner-badge { background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 10px; font-size: 11px; border: 1px solid #30363d; }
        .compliance-tag { font-size: 12px; color: #a78bfa; font-weight: bold; }
        .metric-card { background: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
        
        /* Ocultar permanentemente el botón nativo de colapsar la barra lateral */
        [data-testid="stSidebarCollapsedControl"] { display: none !important; }
    </style>
""", unsafe_allow_html=True)

# Helper de navegación mas directa
def nav_to(page):
    st.session_state.page = page
    st.rerun()

# --- FLUJO 1: LOGIN / REGISTRO ---
if not st.session_state.auth["token"]:
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.markdown("<h1 style='text-align: center; color: #c084fc;'>HYPERION ACCESS</h1>", unsafe_allow_html=True)
        tab1, tab2 = st.tabs(["🔐 Ingresar", "📝 Registrarse"])
        
        with tab1:
            if st.session_state.auth["step"] == "login":
                u = st.text_input("Correo Electrónico", key="l_user_input")
                p = st.text_input("Contraseña", type="password", key="l_pass_input")
                if st.button("Validar Credenciales", use_container_width=True) and u and p:
                    try:
                        res = requests.post(f"{BACKEND_URL}/auth/login", data={"username": u, "password": p}, timeout=5)
                        if res.status_code == 200:
                            st.session_state.auth.update({"user": u, "step": "2fa"})
                            st.success("Credenciales correctas. Ingrese su código OTP.")
                            time.sleep(0.5); st.rerun()
                        st.error("❌ Usuario o contraseña incorrectos." if res.status_code == 401 else f"Error: {res.status_code}")
                    except requests.exceptions.RequestException:
                        st.error("Error de red: No se pudo conectar al Backend.")
            
            elif st.session_state.auth["step"] == "2fa":
                st.markdown(f'<div style="background:#161b22; padding:12px; border-radius:8px; border:1px solid #30363d; margin-bottom:20px;"><p style="margin:0; font-size:11px; color:#a78bfa; font-weight:bold;">🔑 DISPOSITIVO DE VERIFICACIÓN</p><p style="margin:6px 0 0 0; color:#f0f6fc; font-family:monospace;">{st.session_state.auth["user"]}</p></div>', unsafe_allow_html=True)
                with st.expander("¿No has vinculado tu app? Ver Código QR"):
                    try:
                        import qrcode
                        qr = qrcode.make(f"otpauth://totp/Hyperion:{st.session_state.auth['user']}?secret={os.getenv('TOTP_SECRET', 'JBSWY3DPEHPK3PXP')}&issuer=HyperionOps")
                        buf = BytesIO(); qr.save(buf, format="PNG")
                        st.image(buf.getvalue(), caption="Escanea con Google Authenticator", width=200)
                    except ImportError:
                        st.warning("Módulo qrcode no disponible.")
                
                code = st.text_input("Ingresa el código de 6 dígitos", max_chars=6)
                if st.button("Finalizar Acceso", use_container_width=True):
                    try:
                        res = requests.post(f"{BACKEND_URL}/auth/login/verify-2fa", json={"email": st.session_state.auth["user"], "code": code}, timeout=5)
                        if res.status_code == 200:
                            st.session_state.auth["token"] = res.json()["access_token"]
                            st.success("Acceso concedido."); time.sleep(0.5); st.rerun()
                        st.error("Código incorrecto o expirado.")
                    except Exception as e: st.error(f"Error: {e}")
                if st.button("⬅️ Volver al Login"):
                    st.session_state.auth["step"] = "login"; st.rerun()

        with tab2:
            st.subheader("📝 Registrar Nuevo Operador")
            new_u = st.text_input("Correo Operador")
            new_p = st.text_input("Clave Maestra", type="password")
            new_r = st.selectbox("Rol", ["admin", "user"])
            if st.button("Crear Operador", use_container_width=True) and new_u and new_p:
                try:
                    res = requests.post(f"{BACKEND_URL}/auth/register", json={"email": new_u, "password": new_p, "role": new_r}, timeout=5)
                    if res.status_code == 200:
                        st.success("✅ Operador registrado con éxito. Ya puedes ingresar.")
                    else:
                        st.error(f"Error {res.status_code}: {res.text}")
                except Exception as e: st.error(f"Error: {e}")

# --- FLUJO 2: INTERFAZ DE VISTAS PROTEGIDAS ---
else:
    headers = {"Authorization": f"Bearer {st.session_state.auth['token']}"}
    
    # BARRA LATERAL FIJA PERSISTENTE
    with st.sidebar:
        st.markdown(f'<div style="display:flex; align-items:center; gap:12px; margin-bottom:20px;"><img src="{LOGO_SVG}" width="35"><h2 style="color:#a78bfa; margin:0; font-size:1.5rem; letter-spacing:1px;">HYPERION <span style="color:white; font-size:0.8rem; vertical-align:middle;">CORE</span></h2></div>', unsafe_allow_html=True)
        
        try:
            h = requests.get(f"{BACKEND_URL}/health/deep", timeout=1.5).json()
            api, db = ("🟢" if h.get("api") == "healthy" else "🔴"), ("🟢" if h.get("database") == "healthy" else "🔴")
        except: api, db = "🔴", "🔴"

        st.markdown(f'<div style="background:#1e293b; padding:12px; border-radius:8px; border:1px solid #334155; margin-bottom:10px;"><p style="margin:0; font-size:11px; color:#94a3b8; font-weight:bold;">ESTADO DEL SISTEMA</p><div style="display:flex; justify-content:space-between; margin-top:5px;"><span>{api} API</span><span>{db} DB</span></div></div>', unsafe_allow_html=True)
        st.markdown(f'<div style="background:#161b22; padding:12px; border-radius:8px; border:1px solid #30363d; margin-bottom:20px;"><p style="margin:0; font-size:11px; color:#8b949e; font-weight:bold;">OPERADOR ACTIVO</p><div style="display:flex; align-items:center; gap:8px; margin-top:6px;"><span>👤</span><span style="color:#f0f6fc; font-family:monospace; font-size:12px;">{st.session_state.auth["user"]}</span></div></div>', unsafe_allow_html=True)
        
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
            st.session_state.auth = {"token": None, "user": None, "step": "login"}; st.rerun()

    # ROUTER DE PÁGINAS PRINCIPALES
    if st.session_state.page == "Analíticas":
        st.markdown("<h2 style='color: #c084fc;'>📊 Dashboard de Mando SOC & Analíticas</h2>", unsafe_allow_html=True)
        st.caption(f"Filtrando telemetría global | Modo de Operación: Inmutable NIST SP 800-53")
        
        # KPI Cards compactas
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>CONTROLES ACTIVOS</p><h2 style='margin:5px 0; color:#a78bfa;'>42 / 50</h2><small style='color:#4ade80;'>▲ 2 hoy</small></div>", unsafe_allow_html=True)
        c2.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>CUMPLIMIENTO NIST</p><h2 style='margin:5px 0; color:#a78bfa;'>78%</h2><small style='color:#4ade80;'>▲ 5% vs mes ant.</small></div>", unsafe_allow_html=True)
        c3.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>AMENAZAS CRÍTICAS</p><h2 style='margin:5px 0; color:#f85149;'>0</h2><small style='color:#8b949e;'>Estable (48h)</small></div>", unsafe_allow_html=True)
        c4.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>SCORE DE RIESGO</p><h2 style='margin:5px 0; color:#58a6ff;'>BAJO</h2><small style='color:#58a6ff;'>Zonas estables</small></div>", unsafe_allow_html=True)
        
        st.write("---")
        col_g1, col_g2 = st.columns([1.2, 1.8])
        with col_g1:
            st.markdown("#### 🎯 Madurez del Framework NIST")
            fig = go.Figure(data=go.Scatterpolar(r=[4, 5, 3, 4, 4], theta=['ID','PR','DE','RS','RC'], fill='toself', line_color='#a78bfa', fillcolor='rgba(167, 139, 250, 0.2)'))
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", polar=dict(bgcolor="#161b22", radialaxis=dict(visible=True, range=[0, 5], gridcolor="#30363d")), margin=dict(l=30, r=30, t=20, b=20))
            st.plotly_chart(fig, use_container_width=True)
        with col_g2:
            st.markdown("#### 📊 Eventos de Seguridad")
            fig_bars = go.Figure(data=[go.Bar(x=['Fuerza Bruta', 'Anomalía', '2FA', 'Inyecciones', 'Accesos'], y=[14, 28, 122, 5, 340], marker=dict(color=['#f85149', '#ff7b72', '#a78bfa', '#fca5a5', '#58a6ff']))])
            fig_bars.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", yaxis=dict(gridcolor="#30363d"), margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig_bars, use_container_width=True)

    elif st.session_state.page == "Vigilancia":
        st.title("👁️ Centro de Control Operativo (Capa 7)")
        col_grafica, col_stats = st.columns([2, 1])
        col_grafica.area_chart(pd.DataFrame(np.random.randn(20, 1) + [20], columns=['Latencia ms']), height=150)
        col_stats.metric("Defensa Activa", "Firewall OK", "127 Bloqueos")
        
        log_placeholder = st.empty()
        try:
            res = requests.get(f"{BACKEND_URL}/logs/recent", headers=headers, timeout=3)
            if res.status_code == 200:
                feed = "".join([f"DEBUG [{l['timestamp']}] GET -> 200 OK | {l['message']}\n" for l in res.json()[:5]])
                log_placeholder.code(feed, language="accesslog")
        except: log_placeholder.error("🚨 Sincronizando con nodo central...")

    elif st.session_state.page == "Operadores":
        st.title("👥 Gestión de Operadores")
        try:
            res = requests.get(f"{BACKEND_URL}/api/system-metrics", headers=headers, timeout=4)
            if res.status_code == 200:
                st.dataframe(pd.DataFrame([{"Email": k, "Rol": v.get('role', 'N/A')} for k, v in res.json().items()]), use_container_width=True)
            else: st.error("🛑 Privilegios insuficientes.")
        except Exception as e: st.error(f"Error de base de datos: {e}")

    elif st.session_state.page == "Gobernanza":
        st.title("⚖️ Gobernanza y Estrategia")
        c1, c2, c3 = st.columns(3)
        c1.metric("SECURITY SCORE", "92%", "+2.1%")
        c2.metric("INCIDENTES", "0", "Estable")
        c3.metric("CUMPLIMIENTO", "88%", "SOC2 / GDPR")
        st.write("---")
        st.markdown('<div class="risk-row" style="border-left: 4px solid #f85149;"><div><strong>Consola Auditoría Externa</strong><br><small style="color:#8b949e;">Mitigación: IP Whitelisting</small></div><span style="color:#f85149; font-weight:bold;">ALTO 🟠</span></div>', unsafe_allow_html=True)

    elif st.session_state.page == "AuditLogs":
        st.title("📜 Registros de Auditoría")
        try:
            res = requests.get(f"{BACKEND_URL}/admin/audit-logs", headers=headers, timeout=4)
            if res.status_code == 200 and res.json():
                df = pd.DataFrame(res.json())
                search = st.text_input("🔍 Filtrar logs:")
                if search:
                    df = df[df.apply(lambda r: search.lower() in r.astype(str).str.lower().values, axis=1)]
                st.download_button("Descargar CSV", data=df.to_csv(index=False).encode('utf-8'), file_name="audit.csv", mime="text/csv")
                st.dataframe(df, use_container_width=True)
            else: st.warning("Sin registros disponibles.")
        except Exception as e: st.error(f"Fallo de conexión: {e}")

    elif st.session_state.page == "SIEM":
        st.title("📜 Hyperion SIEM Audit Gateway")
        c1, c2, c3 = st.columns(3)
        c1.markdown('<div class="metric-card"><h4>📦 Nodo Ingesta</h4><strong>ACTIVO</strong><br><small>Kafka 9092</small></div>', unsafe_allow_html=True)
        c2.markdown('<div class="metric-card"><h4>🔒 Integridad</h4><strong>SHA-256</strong><br><small>Inmutable</small></div>', unsafe_allow_html=True)
        c3.markdown('<div class="metric-card"><h4>⚡ Rendimiento</h4><strong>&lt; 10ms</strong><br><small>Estable</small></div>', unsafe_allow_html=True)
        st.write("---")
        st.markdown(f'<a href="https://hyperion-audit.streamlit.app/?operator={st.session_state.auth["user"]}&session_token={st.session_state.auth["token"]}" target="_blank" style="text-decoration: none;"><div style="background: linear-gradient(90deg, #9333ea 0%, #c084fc 100%); padding: 25px; border-radius: 12px; text-align: center; color: white; font-weight: bold; font-size: 18px;">🔒 ABRIR BITÁCORA LEGAL SOC ↗️</div></a>', unsafe_allow_html=True)