import subprocess
import sys

# Script de emergencia: fuerza la instalación de plotly si el servidor lo ignora
try:
    import plotly
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "plotly"])

# Script de emergencia: fuerza la instalación de qrcode si el servidor lo ignora
try:
    import qrcode
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode"])

import streamlit as st
import requests
import os
import time
import pandas as pd
import plotly.graph_objects as go
import numpy as np

# --- CARGAR VARIABLES DESDE EL ENTORNO O SECRETS ---
BACKEND_URL = os.getenv("BACKEND_URL", "https://hyperion-pi-nine.vercel.app/")
try:
    if st.secrets and "BACKEND_URL" in st.secrets:
        BACKEND_URL = st.secrets["BACKEND_URL"]
except Exception:
    pass

if BACKEND_URL.endswith("/"):
    BACKEND_URL = BACKEND_URL.rstrip("/")

BACKEND_INTERNAL = BACKEND_URL
LOGO_SVG = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>"

st.set_page_config(page_title="Hyperion Core", page_icon=LOGO_SVG, layout="wide")

# --- CSS INYECTADO: CLONACIÓN AVANZADA DEL SIDEBAR DE LA IMAGEN ---
st.markdown("""
    <style>
        /* Paleta de fondo general */
        .stApp { background-color: #07090e; }
        
        h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; letter-spacing: -0.5px; }
        h2 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; }
        h3 { color: #58a6ff !important; font-family: 'Courier New', monospace; font-weight: bold; }
        h4 { color: #ffffff !important; }

        /* Contenedor estructural del Sidebar Fijo */
        [data-testid="stSidebar"] { 
            background-color: #090d14 !important; 
            border-right: 1px solid rgba(167, 139, 250, 0.15) !important; 
            min-width: 280px !important; 
        }
        [data-testid="stSidebarCollapsedControl"] { display: none !important; } /* Inhabilitar colapso para consistencia */
        
        /* Contenedor del Perfil de Operador (Clonado de la imagen) */
        .user-profile-card {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 24px;
            padding: 4px 8px;
        }
        .user-avatar {
            width: 44px;
            height: 44px;
            background-color: #00b074; /* Color verde esmeralda de la imagen */
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 22px;
            font-weight: bold;
            box-shadow: 0 4px 12px rgba(0, 176, 116, 0.2);
        }
        .user-info {
            display: flex;
            flex-direction: column;
        }
        .user-name {
            color: #ffffff !important;
            font-family: 'Segoe UI', sans-serif;
            font-weight: 600;
            font-size: 1.05rem;
            line-height: 1.2;
        }
        .user-role {
            color: #64748b !important;
            font-family: 'Segoe UI', sans-serif;
            font-size: 0.8rem;
            font-weight: 500;
            margin-top: 2px;
        }

        /* Buscador Simulado Premium (Clonado de la imagen) */
        .search-box-simulated {
            background-color: #0f131a;
            border: 1px solid #1e2530;
            border-radius: 8px;
            padding: 10px 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            color: #475569;
            font-family: 'Segoe UI', sans-serif;
            font-size: 0.9rem;
        }
        .search-shortcut {
            background: #181f2a;
            border: 1px solid #2d3748;
            border-radius: 4px;
            padding: 1px 5px;
            font-size: 0.75rem;
            color: #64748b;
            font-family: monospace;
        }

        /* Botones de menú interactivos - Formato Flat con Hover Integrado */
        div.stSidebar div.stButton > button { 
            background-color: transparent !important; 
            color: #94a3b8 !important; 
            border: 1px solid transparent !important; 
            border-radius: 8px !important; 
            transition: all 0.2s ease-in-out !important; 
            text-align: left !important; 
            padding: 10px 14px !important; 
            width: 100% !important;
            font-size: 0.95rem !important;
            font-family: 'Segoe UI', sans-serif !important;
            font-weight: 500 !important;
        }
        
        /* Al hacer Hover en cualquier elemento del menú */
        div.stSidebar div.stButton > button:hover { 
            color: #ffffff !important; 
            background-color: #0f141c !important; 
            border-color: rgba(255, 255, 255, 0.02) !important;
        }
        
        /* Estado ACTIVO / SELECCIONADO (Simula la celda verde de 'Panel' en la imagen) */
        /* Al hacer clic o estar enfocado se transforma en la celda destacada con tinte Hyperion */
        div.stSidebar div.stButton > button:focus, div.stSidebar div.stButton > button:active {
            background-color: rgba(0, 176, 116, 0.12) !important; /* Tinte verde sutil */
            border: 1px solid rgba(0, 176, 116, 0.25) !important;
            color: #00b074 !important; /* Letras verdes exactas */
            box-shadow: 0 4px 12px rgba(0,0,0,0.15) !important;
        }

        /* Tarjetas de Datos de la derecha (Estilo HUD) */
        .kpi-card { 
            background: #0b0f17; 
            padding: 20px; 
            border-radius: 12px; 
            border: 1px solid rgba(167, 139, 250, 0.2); 
            box-shadow: 0 0 30px rgba(88, 166, 255, 0.03);
        }
        .metric-card { 
            background: linear-gradient(135deg, #0f172a 0%, #020617 100%); 
            padding: 15px; 
            border-radius: 10px; 
            border: 1px solid rgba(167, 139, 250, 0.3); 
        }
        .risk-row { 
            background: rgba(11, 15, 23, 0.9); 
            padding: 15px; 
            border-radius: 10px; 
            border: 1px solid rgba(167, 139, 250, 0.2); 
            margin-bottom: 12px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            backdrop-filter: blur(10px);
        }
        .stDataFrame { background-color: #0b0f17; border: 1px solid #1f2937; }
        .owner-badge { background: #0f172a; color: #cbd5e1; padding: 2px 8px; border-radius: 10px; font-size: 11px; border: 1px solid rgba(255,255,255,0.1); }
        .compliance-tag { font-size: 12px; color: #a78bfa; font-weight: bold; }
        
        footer { visibility: hidden; }
    </style>
""", unsafe_allow_html=True)

# --- SINGLETON DE SESIÓN ---
if "auth" not in st.session_state:
    st.session_state.auth = {"token": None, "user": None, "step": "login"}
if "page" not in st.session_state:
    st.session_state.page = "Analíticas"

def nav_to(page):
    st.session_state.page = page
    st.rerun()

# --- CONTROL DE FLUJO PRINCIPAL ---
if not st.session_state.auth["token"]:
    # LOGIN PRIVADO
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
                        res = requests.post(f"{BACKEND_INTERNAL}/auth/login", data={"username": u, "password": p}, timeout=5)
                        if res.status_code == 200:
                            st.session_state.auth.update({"user": u, "step": "2fa"})
                            st.success("Credenciales correctas. Ingrese su código OTP.")
                            time.sleep(0.5); st.rerun()
                        st.error("❌ Credenciales incorrectas.")
                    except: st.error("Error de conexión con el Backend.")
            
            elif st.session_state.auth["step"] == "2fa":
                st.write(f"Operador: {st.session_state.auth['user']}")
                code = st.text_input("Código OTP", max_chars=6)
                if st.button("Finalizar Acceso", use_container_width=True):
                    try:
                        res = requests.post(f"{BACKEND_INTERNAL}/auth/login/verify-2fa", json={"email": st.session_state.auth["user"], "code": code}, timeout=5)
                        if res.status_code == 200:
                            st.session_state.auth["token"] = res.json()["access_token"]
                            st.success("Acceso concedido."); time.sleep(0.5); st.rerun()
                        st.error("Código incorrecto.")
                    except: st.error("Error al validar 2FA.")
                if st.button("⬅️ Volver"): st.session_state.auth["step"] = "login"; st.rerun()

        with tab2:
            st.subheader("📝 Registrar Nuevo Operador")
            new_u = st.text_input("Correo Operador")
            new_p = st.text_input("Clave Maestra", type="password")
            new_r = st.selectbox("Rol", ["admin", "user"])
            if st.button("Crear Operador", use_container_width=True) and new_u and new_p:
                try:
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/register", json={"email": new_u, "password": new_p, "role": new_r}, timeout=5)
                    if res.status_code == 200: st.success("✅ Operador creado.")
                    else: st.error("Fallo al registrar.")
                except: st.error("Error de red.")

else:
    # VISTAS PROTEGIDAS CON NUEVA BARRA LATERAL CLONADA
    with st.sidebar:
        # 1. Perfil del Operador (Clonación Visual de la Imagen)
        user_initial = st.session_state.auth["user"][0].upper() if st.session_state.auth["user"] else "U"
        display_name = st.session_state.auth["user"].split("@")[0].capitalize()
        
        st.markdown(f"""
            <div class="user-profile-card">
                <div class="user-avatar">{user_initial}</div>
                <div class="user-info">
                    <span class="user-name">{display_name}</span>
                    <span class="user-role">ISO 27001 Auditor</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
        
        # 2. Buscador Simulado (Clonación Visual de la Imagen)
        st.markdown("""
            <div class="search-box-simulated">
                <span>🔍 Buscar...</span>
                <span class="search-shortcut">⌘K</span>
            </div>
        """, unsafe_allow_html=True)
        
        # 3. Menú de Navegación de Botones Limpios
        if st.button("🎛️ Panel / Analíticas", use_container_width=True): nav_to("Analíticas")
        if st.button("🔍 Análisis de Brechas", use_container_width=True): nav_to("Vigilancia")
        if st.button("👥 Gestión de Usuarios", use_container_width=True): nav_to("Operadores")
        if st.button("📋 Mapa de Riesgos", use_container_width=True): nav_to("Gobernanza")
        if st.button("🗄️ Centro de Evidencias", use_container_width=True): nav_to("AuditLogs")
        if st.button("📄 Sala de Auditoría (SIEM)", use_container_width=True): nav_to("SIEM")
        
        st.write("---")
        if st.button("🚪 Cerrar Perímetro", use_container_width=True):
            st.session_state.auth = {"token": None, "user": None, "step": "login"}
            st.rerun()

    # Cabecera autorizada
    headers = {"Authorization": f"Bearer {st.session_state.auth['token']}"}
    
    # ENRUTADOR INTERNO DE MÓDULOS (Dashboard Principal)
    if st.session_state.page == "Analíticas":
        st.markdown("<h2 style='color: #c084fc;'>📊 Dashboard de Mando SOC & Analíticas</h2>", unsafe_allow_html=True)
        
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>CONTROLES ACTIVOS</p><h2 style='margin:5px 0; color:#a78bfa;'>42 / 50</h2><small style='color:#4ade80;'>▲ 2 hoy</small></div>", unsafe_allow_html=True)
        c2.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>CUMPLIMIENTO NIST</p><h2 style='margin:5px 0; color:#a78bfa;'>78%</h2><small style='color:#4ade80;'>▲ 5% vs mes ant.</small></div>", unsafe_allow_html=True)
        c3.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>AMENAZAS CRÍTICAS</p><h2 style='margin:5px 0; color:#f85149;'>0</h2><small style='color:#8b949e;'>Estable</small></div>", unsafe_allow_html=True)
        c4.markdown("<div class='kpi-card'><p style='color:#8b949e; margin:0; font-size:12px;'>SCORE DE RIESGO</p><h2 style='margin:5px 0; color:#58a6ff;'>BAJO</h2><small style='color:#58a6ff;'>Zonas estables</small></div>", unsafe_allow_html=True)
        
        st.write("---")
        col_g1, col_g2 = st.columns([1.2, 1.8])
        with col_g1:
            st.markdown("#### 🎯 Madurez del Framework NIST")
            fig = go.Figure(data=go.Scatterpolar(r=[4, 5, 3, 4, 4], theta=['ID','PR','DE','RS','RC'], fill='toself', line_color='#a78bfa', fillcolor='rgba(167, 139, 250, 0.2)'))
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", polar=dict(bgcolor="#0b0f17", radialaxis=dict(visible=True, range=[0, 5], gridcolor="#1e2530")), margin=dict(l=30, r=30, t=20, b=20))
            st.plotly_chart(fig, use_container_width=True)
        with col_g2:
            st.markdown("#### 📊 Eventos de Seguridad")
            fig_bars = go.Figure(data=[go.Bar(x=['Fuerza Bruta', 'Anomalía', '2FA', 'Inyecciones', 'Accesos'], y=[14, 28, 122, 5, 340], marker=dict(color=['#f85149', '#ff7b72', '#a78bfa', '#fca5a5', '#58a6ff']))])
            fig_bars.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", yaxis=dict(gridcolor="#1e2530"), margin=dict(l=20, r=20, t=20, b=20))
            st.plotly_chart(fig_bars, use_container_width=True)

    elif st.session_state.page == "Vigilancia":
        st.title("👁️ Análisis de Brechas (Capa 7)")
        st.area_chart(pd.DataFrame(np.random.randn(20, 1) + [20], columns=['Latencia ms']), height=150)
        st.metric("Defensa Activa", "Firewall OK", "127 Bloqueos")

    elif st.session_state.page == "Operadores":
        st.title("👥 Gestión de Usuarios e Identidades")
        try:
            res = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics", headers=headers, timeout=4)
            if res.status_code == 200:
                st.dataframe(pd.DataFrame([{"Email": k, "Rol": v.get('role', 'N/A')} for k, v in res.json().items()]), use_container_width=True)
            else: st.error("🛑 Privilegios insuficientes.")
        except: st.error("Fallo al conectar con la base de datos.")

    elif st.session_state.page == "Gobernanza":
        st.title("📋 Mapa de Riesgos Corporativos")
        st.markdown('<div class="risk-row" style="border-left: 4px solid #f85149;"><div><strong>Consola Auditoría Externa</strong><br><small style="color:#8b949e;">Mitigación: IP Whitelisting</small></div><span style="color:#f85149; font-weight:bold;">ALTO 🟠</span></div>', unsafe_allow_html=True)

    elif st.session_state.page == "AuditLogs":
        st.title("🗄️ Centro de Evidencias e Historial")
        st.warning("Consola de lectura inmutable.")

    elif st.session_state.page == "SIEM":
        st.title("📄 Sala de Auditoría Legal SIEM")
        st.markdown(f'<a href="https://hyperion-audit.streamlit.app/" target="_blank" style="text-decoration: none;"><div style="background: linear-gradient(90deg, #00b074 0%, #a78bfa 100%); padding: 25px; border-radius: 12px; text-align: center; color: white; font-weight: bold; font-size: 18px;">🔒 ESCALAR A BITÁCORA LEGAL SOC ↗️</div></a>', unsafe_allow_html=True)