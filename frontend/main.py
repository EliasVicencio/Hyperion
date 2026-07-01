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

# --- CARGAR VARIABLES DESDE EL ENTORNO O SECRETS (A PRUEBA DE FALLOS) ---
BACKEND_URL = os.getenv("BACKEND_URL", "https://hyperion-pi-nine.vercel.app/")

# Intentamos leer de st.secrets de forma segura sin romper la app si no existe
try:
    if st.secrets and "BACKEND_URL" in st.secrets:
        BACKEND_URL = st.secrets["BACKEND_URL"]
except Exception:
    # Si Streamlit se queja de que no hay secretos, ignoramos el error
    pass

if BACKEND_URL.endswith("/"):
    BACKEND_URL = BACKEND_URL.rstrip("/")

# Declaración de mapeo de Backends para evitar NameError en las peticiones
BACKEND_INTERNAL = BACKEND_URL
BACKEND_EXTERNAL = BACKEND_URL

LOGO_SVG = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>"

st.set_page_config(page_title="Hyperion Core", page_icon=LOGO_SVG, layout="wide")

# --- CSS INYECTADO ---
st.markdown("""
    <style>
        .stApp { background-color: #0b0e14; }
        div.stButton > button { background-color: #161b22; color: #f0f6fc; border: 1px solid #30363d; border-radius: 8px; transition: all 0.3s ease; }
        div.stButton > button:hover { border-color: #a78bfa; color: #a78bfa; background-color: #161b22; }
        [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #30363d; }
        [data-testid="stMetricValue"] { color: #a78bfa !important; }
        *:focus { outline: none !important; box-shadow: none !important; }
        .kpi-card { background: #161b22; padding: 20px; border-radius: 12px; border: 1px solid #30363d; }
        .risk-row { background: #0d1117; padding: 15px; border-radius: 10px; border: 1px solid #30363d; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
        .owner-badge { background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 10px; font-size: 11px; border: 1px solid #30363d; }
        .compliance-tag { font-size: 12px; color: #a78bfa; font-weight: bold; }
        .metric-card { background: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
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

# --- CONTROL DE FLUJO PRINCIPAL DE LA INTERFAZ ---
if not st.session_state.auth["token"]:
    # LÓGICA DE ACCESO PÚBLICO (LOGIN / REGISTRO)
    _, col, _ = st.columns([1, 2, 1])
    
    with col:
        st.markdown("<h1 style='text-align: center; color: #c084fc;'>HYPERION ACCESS</h1>", unsafe_allow_html=True)
        tab1, tab2 = st.tabs(["🔐 Ingresar", "📝 Registrarse"])
        
        with tab1:
            if st.session_state.auth["step"] == "login":
                u = st.text_input("Correo Electrónico", key="l_user_input")
                p = st.text_input("Contraseña", type="password", key="l_pass_input")
                
                if st.button("Validar Credenciales", use_container_width=True):
                    if u and p:
                        try:
                            with st.spinner("Verificando identidad..."):
                                res = requests.post(
                                    f"{BACKEND_INTERNAL}/auth/login", 
                                    data={"username": u, "password": p}, 
                                    timeout=10
                                )
                            
                            if res.status_code == 200:
                                st.session_state.auth["user"] = u
                                st.session_state.auth["step"] = "2fa"
                                st.success("Credenciales correctas. Ingrese su código OTP.")
                                time.sleep(0.5)
                                st.rerun()
                            elif res.status_code == 401:
                                st.error("❌ Usuario o contraseña incorrectos.")
                            elif res.status_code == 403:
                                st.error("🚫 Acceso denegado: IP Bloqueada.")
                            else:
                                st.error(f"Error inesperado: {res.status_code}")
                        except requests.exceptions.RequestException:
                            st.error(f"Error de red: No se pudo conectar al Backend central.")
            
            elif st.session_state.auth["step"] == "2fa":
                usuario_limpio = st.session_state.auth['user']
                st.markdown(f"""
                    <div style="background: #161b22; padding: 12px; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 20px;">
                        <p style='margin:0; font-size:11px; color:#a78bfa; font-weight:bold;'>🔑 DISPOSITIVO DE VERIFICACIÓN</p>
                        <div style='display: flex; align-items: center; gap: 8px; margin-top: 6px;'>
                            <span style='font-size: 13px; color: #f0f6fc; font-family: monospace;'>{usuario_limpio}</span>
                        </div>
                    </div>
                """, unsafe_allow_html=True)
                
                with st.expander("¿No has vinculado tu app? Ver Código QR"):
                    import qrcode
                    from io import BytesIO
                    
                    secret = os.getenv('TOTP_SECRET', 'JBSWY3DPEHPK3PXP')
                    otp_uri = f"otpauth://totp/Hyperion:{st.session_state.auth['user']}?secret={secret}&issuer=HyperionOps"
                    
                    qr = qrcode.make(otp_uri)
                    buf = BytesIO()
                    qr.save(buf, format="PNG")
                    st.image(buf.getvalue(), caption="Escanea con Google Authenticator", width=200)
                
                code = st.text_input("Ingresa el código de 6 dígitos", max_chars=6, key="otp_input")
                
                if st.button("Finalizar Acceso", use_container_width=True):
                    try:
                        res = requests.post(
                            f"{BACKEND_INTERNAL}/auth/login/verify-2fa", 
                            json={"email": st.session_state.auth["user"], "code": code},
                            timeout=5
                        )
                        
                        if res.status_code == 200:
                            st.session_state.auth["token"] = res.json()["access_token"]
                            st.success("Acceso concedido.")
                            time.sleep(0.5)
                            st.rerun()
                        else:
                            st.error(f"Código incorrecto o expirado (Error {res.status_code})")
                    except Exception as e:
                        st.error(f"Error de conexión: {e}")
                
                if st.button("⬅️ Volver al Login"):
                    st.session_state.auth["step"] = "login"
                    st.rerun()

        with tab2:
            st.subheader("📝 Registrar Nuevo Operador")
            new_u = st.text_input("Correo Operador", key="r_user")
            new_p = st.text_input("Clave Maestra", type="password", key="r_pass")
            new_r = st.selectbox("Rol", ["admin", "user"], key="r_role")
            
            if st.button("Crear Operador", use_container_width=True):
                if not new_u or not new_p:
                    st.warning("⚠️ Por favor, completa todos los campos.")
                else:
                    try:
                        with st.spinner("Comunicando con el nodo central..."):
                            res = requests.post(
                                f"{BACKEND_INTERNAL}/auth/register", 
                                json={"email": new_u, "password": new_p, "role": new_r},
                                timeout=10
                            )
                        
                        if res.status_code == 200:
                            st.success(f"✅ Operador **{new_u}** registrado con éxito.")
                            st.balloons()
                            st.info("💡 Ahora puedes ir a la pestaña 'Ingresar' para entrar.")
                        else:
                            try:
                                error_detail = res.json().get('detail', 'Error desconocido.')
                            except:
                                error_detail = res.text
                            st.error(f"❌ Error en registro (Código {res.status_code}): {error_detail}")
                            
                    except Exception as e:
                        st.error(f"🚨 Ocurrió un fallo inesperado en la solicitud de red: {e}")

else:
    # VISTAS PROTEGIDAS (EL USUARIO YA TIENE UN TOKEN VÁLIDO)
    
    # Renderizar primero la barra lateral (Sidebar)
    with st.sidebar:
        st.markdown(f"""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                <img src="{LOGO_SVG}" width="35">
                <h2 style="color: #a78bfa; margin: 0; font-size: 1.5rem; letter-spacing: 1px;">
                    HYPERION <span style="color: white; font-size: 0.8rem; vertical-align: middle;">CORE</span>
                </h2>
            </div>
        """, unsafe_allow_html=True)
        
        try:
            h = requests.get(f"{BACKEND_INTERNAL}/health/deep", timeout=2)
            health_data = h.json()
            api_status = "🟢" if health_data.get("api") == "healthy" else "🔴"
            db_status = "🟢" if health_data.get("database") == "healthy" else "🔴"
        except:
            api_status, db_status = "🔴", "🔴"

        st.markdown(f"""
            <div style="background: #1e293b; padding: 12px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 10px;">
                <p style='margin:0; font-size:11px; color:#94a3b8; font-weight:bold;'>ESTADO DEL SISTEMA</p>
                <div style='display: flex; justify-content: space-between; margin-top: 5px;'>
                    <span style='font-size:13px;'>{api_status} API</span>
                    <span style='font-size:13px;'>{db_status} DB</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

        # --- BLOQUE CORREGIDO DEL OPERADOR (SIN LINK A OUTLOOK) ---
        usuario_limpio = st.session_state.auth['user']
        st.markdown(f"""
            <div style="background: #161b22; padding: 12px; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 20px;">
                <p style='margin:0; font-size:11px; color:#8b949e; font-weight:bold;'>OPERADOR ACTIVO</p>
                <div style='display: flex; align-items: center; gap: 8px; margin-top: 6px;'>
                    <span style='font-size: 14px;'>👤</span>
                    <span style='font-size: 13px; color: #f0f6fc; font-family: monospace;'>{usuario_limpio}</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
        
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

    # Cargar cabecera común para llamadas protegidas
    headers = {"Authorization": f"Bearer {st.session_state.auth['token']}"}
    
    # Enrutamiento interno de paneles
    if st.session_state.page == "Analíticas":
        st.markdown("<h2 style='color: #c084fc;'>📊 Dashboard de Mando SOC & Analíticas</h2>", unsafe_allow_html=True)
        st.markdown("<p style='color: #8b949e; margin-top:-15px;'>Métricas en tiempo real e integridad del framework de ciberseguridad NIST.</p>", unsafe_allow_html=True)
        
        # --- FILTROS DE AUDITORÍA RÁPIDOS ---
        col_f1, col_f2 = st.columns([1, 3])
        with col_f1:
            entorno_sel = st.selectbox("🎯 Entorno de Red", ["Todos los Nodos", "Producción / Azure", "Vercel API Gateway", "Base de Datos Supabase"])
        with col_f2:
            st.markdown("<br>", unsafe_allow_html=True)
            st.caption(f"Filtrando telemetría para: **{entorno_sel}** | Modo de Operación: Inmutable NIST SP 800-53")

        st.write("")

        # --- FILA 1: KPIs DE IMPACTO ---
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown("""
                <div class='kpi-card'>
                    <p style='color: #8b949e; margin:0; font-size:12px;'>CONTROLES ACTIVOS</p>
                    <h2 style='margin:5px 0; color:#a78bfa;'>42 / 50</h2>
                    <small style='color:#4ade80;'>▲ 2 integrados hoy</small>
                </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown("""
                <div class='kpi-card'>
                    <p style='color: #8b949e; margin:0; font-size:12px;'>CUMPLIMIENTO NIST</p>
                    <h2 style='margin:5px 0; color:#a78bfa;'>78%</h2>
                    <small style='color:#4ade80;'>▲ 5% vs mes anterior</small>
                </div>
            """, unsafe_allow_html=True)
        with c3:
            st.markdown("""
                <div class='kpi-card'>
                    <p style='color: #8b949e; margin:0; font-size:12px;'>AMENAZAS CRÍTICAS</p>
                    <h2 style='margin:5px 0; color:#f85149;'>0</h2>
                    <small style='color:#8b949e;'>Estable (Últimas 48h)</small>
                </div>
            """, unsafe_allow_html=True)
        with c4:
            st.markdown("""
                <div class='kpi-card'>
                    <p style='color: #8b949e; margin:0; font-size:12px;'>SCORE TOTAL DE RIESGO</p>
                    <h2 style='margin:5px 0; color:#58a6ff;'>BAJO</h2>
                    <small style='color:#58a6ff;'>Zonas desmitigadas: 0</small>
                </div>
            """, unsafe_allow_html=True)

        st.write("---")

        # --- FILA 2: GRÁFICOS AVANZADOS ---
        col_g1, col_g2 = st.columns([1.2, 1.8])

        with col_g1:
            st.markdown("#### 🎯 Madurez del Framework NIST")
            # Tu gráfico radar mejorado con estilo Cyberpunk
            fig_radar = go.Figure(data=go.Scatterpolar(
                r=[4, 5, 3, 4, 4], 
                theta=['ID (Identificar)','PR (Proteger)','DE (Detectar)','RS (Responder)','RC (Recuperar)'], 
                fill='toself', 
                line_color='#a78bfa',
                fillcolor='rgba(167, 139, 250, 0.2)'
            ))
            fig_radar.update_layout(
                template="plotly_dark", 
                paper_bgcolor="rgba(0,0,0,0)", 
                plot_bgcolor="rgba(0,0,0,0)",
                polar=dict(
                    bgcolor="#161b22",
                    radialaxis=dict(visible=True, range=[0, 5], gridcolor="#30363d"),
                    angularaxis=dict(gridcolor="#30363d")
                ),
                margin=dict(l=40, r=40, t=20, b=20)
            )
            st.plotly_chart(fig_radar, use_container_width=True)

        with col_g2:
            st.markdown("#### 📊 Distribución de Eventos de Seguridad Recientes")
            # Gráfico de barras de procedencia/tipo de ataques simulados
            eventos_tipo = ['Fuerza Bruta', 'Tráfico Anomalía', 'Validación 2FA', 'Inyecciones Bloqueadas', 'Accesos Correctos']
            conteos = [14, 28, 122, 5, 340]
            
            fig_bars = go.Figure(data=[go.Bar(
                x=eventos_tipo, 
                y=conteos,
                marker=dict(
                    color=['#f85149', '#ff7b72', '#a78bfa', '#fca5a5', '#58a6ff'],
                    line=dict(color="#30363d", width=1) # <- Aquí se define correctamente el borde
                )
            )])
            fig_bars.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(gridcolor="#30363d", title="N° Eventos"),
                xaxis=dict(title="Categoría de Log"),
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_bars, use_container_width=True)

        st.write("---")

        # --- FILA 3: VISTA DE TOPOLOGÍA E INFRAESTRUCTURA (RENOVACIÓN CLAVE) ---
        st.markdown("#### 🌐 Topología del Ecosistema Hyperion Core")
        st.caption("Estatus de comunicación de los nodos distribuidos y microservicios.")
        
        c_node1, c_node2, c_node3, c_node4 = st.columns(4)
        
        with c_node1:
            st.markdown("""
                <div style='background: #0d1117; padding: 15px; border-radius: 10px; border: 1px solid #30363d; border-top: 4px solid #4ade80;'>
                    <span style='float: right; color: #4ade80;'>● ONLINE</span>
                    <strong style='color: white;'>🔗 Streamlit UI</strong><br>
                    <small style='color: #8b949e;'>Host: Cloud Edge (Ámsterdam)</small><br>
                    <small style='color: #a78bfa;'>SSL: TLS v1.3 Activo</small>
                </div>
            """, unsafe_allow_html=True)

        with c_node2:
            st.markdown("""
                <div style='background: #0d1117; padding: 15px; border-radius: 10px; border: 1px solid #30363d; border-top: 4px solid #4ade80;'>
                    <span style='float: right; color: #4ade80;'>● ONLINE</span>
                    <strong style='color: white;'>⚡ FastAPI Core</strong><br>
                    <small style='color: #8b949e;'>Host: Vercel Serverless</small><br>
                    <small style='color: #a78bfa;'>Latencia Ingesta: ~12ms</small>
                </div>
            """, unsafe_allow_html=True)

        with c_node3:
            st.markdown("""
                <div style='background: #0d1117; padding: 15px; border-radius: 10px; border: 1px solid #30363d; border-top: 4px solid #4ade80;'>
                    <span style='float: right; color: #4ade80;'>● ONLINE</span>
                    <strong style='color: white;'>🗄️ PostgreSQL DB</strong><br>
                    <small style='color: #8b949e;'>Host: Supabase Cluster</small><br>
                    <small style='color: #a78bfa;'>Pool Conexiones: 3 / 20</small>
                </div>
            """, unsafe_allow_html=True)

        with c_node4:
            st.markdown("""
                <div style='background: #0d1117; padding: 15px; border-radius: 10px; border: 1px solid #30363d; border-top: 4px solid #ff7b72;'>
                    <span style='float: right; color: #ff7b72;'>○ STANDBY</span>
                    <strong style='color: white;'>📦 Kafka Audit Node</strong><br>
                    <small style='color: #8b949e;'>Host: Branch SIEM Inmutable</small><br>
                    <small style='color: #a78bfa;'>Puerto: 9092 Abierto</small>
                </div>
            """, unsafe_allow_html=True)

    elif st.session_state.page == "Vigilancia":
        st.title("🕵️ Centro de Control Operativo (Capa 7)")
        
        col_grafica, col_stats = st.columns([2, 1])
        with col_grafica:
            st.subheader("📈 Latencia del Motor (ms)")
            chart_data = pd.DataFrame(np.random.randn(20, 1) + [20], columns=['Latencia ms'])
            st.area_chart(chart_data, height=150, use_container_width=True)

        with col_stats:
            st.subheader("🛡️ Defensa Activa")
            st.status("Firewall: **Protegiendo**", state="complete")
            st.metric("Amenazas Bloqueadas (24h)", "127", "+12%")

        st.write("---")
        st.subheader("🖥️ Consola de Tráfico de Red (Deep Packet Inspection)")
        log_placeholder = st.empty()

        for i in range(3):
            try:
                response = requests.get(f"{BACKEND_INTERNAL}/logs/recent", headers=headers, timeout=5)
                if response.status_code == 200:
                    logs = response.json()
                    log_feed = ""
                    for log in logs:
                        ip_falsa = f"192.168.1.{np.random.randint(2, 254)}"
                        metodo = np.random.choice(["GET", "POST", "PUT", "DELETE"])
                        log_feed += f"DEBUG [{log['timestamp']}] {metodo} {ip_falsa} -> HTTP/1.1 200 OK | {log['message']}\n"
                    log_placeholder.code(log_feed, language="accesslog")
                else:
                    log_placeholder.error(f"⚠️ Error de enlace con el Backend: {response.status_code}")
            except:
                log_placeholder.error("🚨 Nodo Central fuera de alcance. Reintentando...")
            time.sleep(2)

    elif st.session_state.page == "Operadores":
        st.title("👥 Gestión de Operadores")
        try:
            r = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics", headers=headers)
            if r.status_code == 200:
                usuarios = r.json()
                if usuarios:
                    data_list = [{"Email": k, "Rol": v.get('role', 'N/A')} for k, v in usuarios.items()]
                    st.dataframe(pd.DataFrame(data_list), use_container_width=True)
                else: 
                    st.info("No hay operadores registrados en la base de datos.")
            else: 
                st.error("🛑 Acceso Denegado: Se requieren privilegios de Admin.")
        except Exception as e: 
            st.error(f"Error al conectar con la base de datos: {e}")
        
    elif st.session_state.page == "Gobernanza":
        st.title("⚖️ Centro de Gobernanza y Estrategia")
        col_a, col_b, col_c = st.columns(3)
        
        with col_a:
            st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
            st.metric("SECURITY SCORE", "92%", "+2.1%")
            st.line_chart([85, 87, 86, 89, 90, 92], height=50, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_b:
            st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
            st.metric("INCIDENTES ABIERTOS", "0", "Stable", delta_color="normal")
            st.write("🛡️ Sistema íntegro")
            st.markdown('</div>', unsafe_allow_html=True)

        with col_c:
            st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
            st.metric("CUMPLIMIENTO TOTAL", "88%", "SOC2/GDPR")
            st.markdown("""
                <div style="margin-top:10px;">
                    <span class="compliance-tag">GDPR: 85%</span> | 
                    <span class="compliance-tag">SOC2: 92%</span> | 
                    <span class="compliance-tag">ISO: 87%</span>
                </div>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        st.write("---")
        col_left, col_right = st.columns([1.8, 1])

        with col_left:
            st.subheader("🛡️ Gestión de Activos y Riesgos")
            st.markdown("""
                <div class="risk-row" style="border-left: 4px solid #f85149;">
                    <div>
                        <strong style="font-size:16px;">Consola Auditoría Externa</strong><br>
                        <span style="color:#8b949e; font-size:13px;">Mitigación: IP Whitelisting (En progreso)</span><br>
                        <span class="owner-badge">Dueño: @carlos.seg</span>
                    </div>
                    <div style="text-align:right;">
                        <span style="color:#f85149; font-weight:bold; font-size:18px;">🟠</span><br>
                        <small style="color:#f85149;">ALTO</small>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        with col_right:
            st.subheader("📋 Roadmap y Auditoría")
            with st.expander("📅 Próximos Hitos", expanded=True):
                st.write("**Auditoría Externa:** `2026-05-25`")
                st.write("**Revisión de Accesos:** `En 3 días`")
            
            st.write("---")
            st.subheader("📈 Auditoría y Reportes")
            with st.container(border=True):
                st.write("**Próxima Auditoría Interna:**")
                st.code("2026-05-25 (En 14 días)")
                st.write("**Reporte SOC2:**")
                st.progress(0.7)
                
                if st.button("📥 Generar Reporte Ejecutivo PDF", use_container_width=True, key="btn_reporte_gob"):
                    with st.spinner('Compilando métricas...'):
                        time.sleep(1.5)
                        st.success("✅ Reporte 'Hyperion_Executive_Q2.pdf' listo.")
                        st.download_button("Click para descargar", "Contenido PDF simulado", "Hyperion_Report.pdf", key="dl_gob")

    elif st.session_state.page == "AuditLogs":
        st.title("📜 Registros de Auditoría del Sistema")
        st.info("Historial de acciones críticas almacenadas en PostgreSQL.")

        try:
            r = requests.get(f"{BACKEND_INTERNAL}/admin/audit-logs", headers=headers)
            
            if r.status_code == 200:
                logs = r.json()
                if logs:
                    df_logs = pd.DataFrame(logs)
                    
                    col_search, col_exp = st.columns([2, 1])
                    with col_search:
                        search = st.text_input("🔍 Filtrar logs:", placeholder="Ej: admin, login...")
                    
                    if search:
                        df_logs = df_logs[df_logs.apply(lambda row: search.lower() in row.astype(str).str.lower().values, axis=1)]

                    with col_exp:
                        st.write("📤 **Exportar**")
                        csv = df_logs.to_csv(index=False).encode('utf-8')
                        st.download_button(label="Descargar CSV", data=csv, file_name="audit_report.csv", mime="text/csv", use_container_width=True)

                    st.dataframe(df_logs, use_container_width=True)
                    st.caption(f"Mostrando {len(df_logs)} registros.")
                else:
                    st.warning("No hay registros de auditoría en la base de datos.")
            else:
                st.error(f"🛑 Error {r.status_code}: No autorizado para auditar.")
        except Exception as e:
            st.error(f"🚨 Error de conexión: {e}")

    elif st.session_state.page == "SIEM":
        st.title("📜 Hyperion SIEM Audit Gateway")
        
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown('<div class="metric-card"><h4 style="margin:0; color:#9333ea;">📦 Nodo Ingesta</h4><p style="font-size:24px; font-weight:bold; margin:0;">ACTIVO</p><small style="color:#4ade80;">Kafka 9092</small></div>', unsafe_allow_html=True)
        with col_b:
            st.markdown('<div class="metric-card"><h4 style="margin:0; color:#9333ea;">🔒 Integridad</h4><p style="font-size:24px; font-weight:bold; margin:0;">SHA-256</p><small style="color:#4ade80;">Inmutable</small></div>', unsafe_allow_html=True)
        with col_c:
            st.markdown('<div class="metric-card"><h4 style="margin:0; color:#9333ea;">⚡ Rendimiento</h4><p style="font-size:24px; font-weight:bold; margin:0;">< 10ms</p><small style="color:#4ade80;">Latencia de enlace</small></div>', unsafe_allow_html=True)

        st.write("")
        st.write("---")
        
        left_col, right_col = st.columns([2, 1])

        with left_col:
            st.subheader("Enlace Desacoplado")
            st.info("Haga clic abajo para saltar de forma segura al nodo inmutable de auditoría legal.")
            
            URL_DESPLIEGUE_RAMA_NUEVA = "https://hyperion-audit.streamlit.app/" 
            
            usuario_actual = st.session_state.auth["user"]
            token_actual = st.session_state.auth["token"]
            
            url_destino_con_parametros = f"{URL_DESPLIEGUE_RAMA_NUEVA}/?operator={usuario_actual}&session_token={token_actual}"
            
            st.markdown(f"""
                <a href="{url_destino_con_parametros}" target="_blank" style="text-decoration: none;">
                    <div style="background: linear-gradient(90deg, #9333ea 0%, #c084fc 100%); padding: 25px; border-radius: 12px; text-align: center; color: white; font-weight: bold; font-size: 18px; box-shadow: 0 4px 20px rgba(147, 51, 234, 0.4); transition: transform 0.2s;">
                        🔒 ABRIR BITÁCORA LEGAL ↗️
                    </div>
                </a>
            """, unsafe_allow_html=True)

        with right_col:
            st.subheader("Estatus de Conexión")
            st.success(f"Sesión validada para: {st.session_state.auth['user']}")
            
            # --- NUEVO APARTADO: TELEMETRÍA VPN PARA CONEXIÓN REMOTA ---
            # Simulamos una verificación de procedencia de IP
            es_remoto = True # Cambiar a False para pruebas de nodo local
            vpn_activa = True # Estado del túnel cifrado
            ip_origen = "10.8.0.42" if vpn_activa else "186.105.4.12"
            
            st.markdown("### 🌐 Auditoría de Red Inbound")
            if es_remoto:
                if vpn_activa:
                    st.markdown(f"""
                        <div style="background: rgba(74, 222, 128, 0.1); padding: 12px; border-radius: 8px; border: 1px solid #4ade80; margin-bottom: 15px;">
                            <p style='margin:0; font-size:11px; color:#4ade80; font-weight:bold;'>🔐 TÚNEL VPN DETECTADO</p>
                            <p style='margin:4px 0 0 0; font-size:13px; color:#f0f6fc;'>Acceso Remoto: <b>Protegido</b></p>
                            <small style='color:#8b949e; font-family: monospace;'>IP Asignada: {ip_origen} (Virtual)</small>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                        <div style="background: rgba(248, 81, 73, 0.1); padding: 12px; border-radius: 8px; border: 1px solid #f85149; margin-bottom: 15px;">
                            <p style='margin:0; font-size:11px; color:#ff7b72; font-weight:bold;'>🚨 ACCESO REMOTO INSEGURO</p>
                            <p style='margin:4px 0 0 0; font-size:13px; color:#f0f6fc;'>Conexión sin cifrar fuera del perímetro</p>
                            <small style='color:#ff7b72; font-family: monospace;'>IP Alerta: {ip_origen} (Pública)</small>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                    <div style="background: #161b22; padding: 12px; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 15px;">
                        <p style='margin:0; font-size:11px; color:#a78bfa; font-weight:bold;'>🏢 NODO LOCAL SOC</p>
                        <p style='margin:4px 0 0 0; font-size:13px; color:#f0f6fc;'>Conexión interna por Intranet Física</p>
                        <small style='color:#8b949e; font-family: monospace;'>Interfaz: eth0 (Segmento ICS)</small>
                    </div>
                """, unsafe_allow_html=True)
            
            st.caption("Los tokens de sesión expiran automáticamente conforme a las políticas NIST.")