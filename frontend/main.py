from frontend.dashboard import API_URL
import streamlit as st
import requests
import os
import time
import pandas as pd
import plotly.graph_objects as go
import io

# --- CONFIGURACIÓN ESTÁTICA ---
    
# --- CONFIGURACIÓN DE PRODUCCIÓN ---
# En producción, BACKEND_INTERNAL es para la comunicación entre contenedores (Docker Net)
# BACKEND_EXTERNAL es la IP que el navegador del usuario final verá.
URL_BACKEND_RENDER = "https://hyperion-gcic.onrender.com"

BACKEND_INTERNAL = URL_BACKEND_RENDER
BACKEND_EXTERNAL = URL_BACKEND_RENDER

LOGO_SVG = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>"

if "BACKEND_URL" in st.secrets:
    BACKEND_INTERNAL = st.secrets["BACKEND_URL"]

st.set_page_config(page_title="Hyperion Ops", page_icon=LOGO_SVG, layout="wide")

# --- CSS INYECTADO (ESTÉTICA DARK) ---
st.markdown("""
    <style>
        /* Fondo total de la aplicación */
        .stApp {
            background-color: #0b0e14;
        }

        /* Cambiar el color de los botones (quitar el azul) */
        div.stButton > button {
            background-color: #161b22;
            color: #f0f6fc;
            border: 1px solid #30363d;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        /* Efecto Hover de los botones en Púrpura */
        div.stButton > button:hover {
            border-color: #a78bfa;
            color: #a78bfa;
            background-color: #161b22;
        }

        /* Estilo para el Sidebar */
        [data-testid="stSidebar"] {
            background-color: #0d1117;
            border-right: 1px solid #30363d;
        }

        /* Estilo de las métricas para que no usen azul */
        [data-testid="stMetricValue"] {
            color: #a78bfa !important;
        }
        
        /* Quitar líneas azules de enfoque */
        *:focus {
            outline: none !important;
            box-shadow: none !important;
        }
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
        # Logo y Título alineados en la misma línea
        st.markdown(f"""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                <img src="{LOGO_SVG}" width="35">
                <h2 style="color: #a78bfa; margin: 0; font-size: 1.5rem; letter-spacing: 1px;">
                    HYPERION <span style="color: white; font-size: 0.8rem; vertical-align: middle;">CORE</span>
                </h2>
            </div>
        """, unsafe_allow_html=True)
        
        # --- WIDGET DE SALUD ---
        try:
            # Importante: Asegúrate de que BACKEND_INTERNAL esté bien definido
            h = requests.get(f"{BACKEND_INTERNAL}/health/deep", timeout=2)
            health_data = h.json()
            api_status = "🟢" if health_data.get("api") == "healthy" else "🔴"
            db_status = "🟢" if health_data.get("database") == "healthy" else "🔴"
        except:
            api_status, db_status = "🔴", "🔴"

        # Widget visual
        st.markdown(f"""
            <div style="background: #1e293b; padding: 12px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 10px;">
                <p style='margin:0; font-size:11px; color:#94a3b8; font-weight:bold;'>ESTADO DEL SISTEMA</p>
                <div style='display: flex; justify-content: space-between; margin-top: 5px;'>
                    <span style='font-size:13px;'>{api_status} API</span>
                    <span style='font-size:13px;'>{db_status} DB</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.write(f"👤 **Usuario:** {st.session_state.auth['user']}")
        st.write("---")
        
        # Botones de Navegación
        if st.button("📊 Analíticas", use_container_width=True): nav_to("Analíticas")
        if st.button("👁️ Vigilancia", use_container_width=True): nav_to("Vigilancia")
        if st.button("👥 Operadores", use_container_width=True): nav_to("Operadores")
        st.write("---")
        # Añade esto en tu lista de botones del sidebar
        if st.button("⚖️ Gobernanza", use_container_width=True): nav_to("Gobernanza")
        if st.button("📜 Logs de Auditoría", use_container_width=True): nav_to("AuditLogs")
        if st.button("📜 SIEM Audit", use_container_width=True): nav_to("SIEM")
        
        st.write("---")
        if st.button("🚪 Cerrar Sesión", use_container_width=True):
            st.session_state.auth = {"token": None, "user": None, "step": "login"}
            st.rerun()

# --- LÓGICA DE ACCESO (VISTA PRINCIPAL) ---

# 1. Verificamos si NO hay token (Pantalla de Acceso)
if not st.session_state.auth["token"]:
    _, col, _ = st.columns([1, 2, 1])
    
    with col:
        st.markdown("<h1 style='text-align: center; color: #c084fc;'>HYPERION ACCESS</h1>", unsafe_allow_html=True)
        
        # Guardamos la pestaña activa en session_state para que no se pierda
        tab1, tab2 = st.tabs(["🔐 Ingresar", "📝 Registrarse"])
        
        with tab1:
            if st.session_state.auth["step"] == "login":
                u = st.text_input("Correo Electrónico", key="l_user_input")
                p = st.text_input("Contraseña", type="password", key="l_pass_input")
                
                if st.button("Validar Credenciales", use_container_width=True):
                    if u and p:
                        try:
                            with st.spinner("Verificando identidad..."):
                                # Enviamos como data (form-data) porque usas OAuth2PasswordRequestForm
                                res = requests.post(
                                    f"{BACKEND_INTERNAL}/auth/login", 
                                    data={"username": u, "password": p}, 
                                    timeout=10
                                )
                            
                            if res.status_code == 200:
                                # Si llegamos aquí, el log de FastAPI debería decir 200 OK
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
                                
                        except requests.exceptions.RequestException as e:
                            # Si el log dice 200 OK pero entras aquí, es un tema de red interna de Docker
                            st.error(f"Error de red: Asegúrate de que BACKEND_URL sea correcto.")
                            print(f"DEBUG: {e}")
            
            elif st.session_state.auth["step"] == "2fa":
                st.info(f"🔑 Verificación para: {st.session_state.auth['user']}")
                
                # --- NUEVA SECCIÓN DE QR EN LOGIN ---
                with st.expander("¿No has vinculado tu app? Ver Código QR"):
                    import qrcode
                    from io import BytesIO
                    
                    # Generamos el URI usando el secreto del .env
                    # IMPORTANTE: El secret debe coincidir con el que usa el Backend
                    secret = os.getenv('TOTP_SECRET', 'JBSWY3DPEHPK3PXP')
                    otp_uri = f"otpauth://totp/Hyperion:{st.session_state.auth['user']}?secret={secret}&issuer=HyperionOps"
                    
                    qr = qrcode.make(otp_uri)
                    buf = BytesIO()
                    qr.save(buf, format="PNG")
                    st.image(buf.getvalue(), caption="Escanea con Google Authenticator", width=200)
                
                # --- CAMPO DE CÓDIGO ---
                code = st.text_input("Ingresa el código de 6 dígitos", max_chars=6, key="otp_input")
                
                if st.button("Finalizar Acceso", use_container_width=True):
                    try:
                        # DEBUG: Imprimir qué enviamos (puedes verlo en la consola)
                        print(f"Enviando OTP: {code} para {st.session_state.auth['user']}")
                        
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
                
                # Opción para volver atrás si se equivocó de usuario
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
                        res = requests.post(
                            f"{BACKEND_INTERNAL}/auth/register", 
                            json={"email": new_u, "password": new_p, "role": new_r},
                            timeout=10
                        )
                        
                        if res.status_code == 200:
                            st.success(f"✅ Operador **{new_u}** registrado con éxito.")
                            st.balloons() # Un pequeño toque visual de éxito
                            st.info("💡 Ahora puedes ir a la pestaña 'Ingresar' para vincular tu app y entrar.")
                        else:
                            # Intentamos extraer el error del backend, si no, mensaje genérico
                            error_detail = res.json().get('detail', 'Error desconocido')
                            st.error(f"❌ Error en registro: {error_detail}")
                            
                    except Exception as e:
                        st.error("🚨 El servidor de registro no responde. Verifica la conexión.")

# --- VISTAS PROTEGIDAS ---
else:
    # Definimos los headers estándar de seguridad (Bearer Token)
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
        st.subheader("🕵️ Vigilancia en Tiempo Real (Modo Optimizado)")
        
        # Contenedor para los logs
        log_container = st.empty()
        
        # Función de refresco con bajo impacto
        def update_logs():
            # Llamada a la API optimizada (máximo 100 registros)
            response = requests.get(f"{API_URL}/logs/recent", headers=headers)
            if response.status_code == 200:
                logs = response.json()
                
                # Construimos el terminal inmutable con el estilo unificado
                log_text = ""
                for log in logs:
                    # Formateamos solo texto ligero, sin HTML pesado por cada línea
                    log_text += f"[{log['timestamp']}] {log['event']}\n"
                
                # Actualizamos todo el bloque de una sola vez para evitar parpadeos y CPU spikes
                log_container.code(log_text, language="bash")

        # Ejecutamos con un sleep para dar respiro al procesador
        update_logs()

    elif st.session_state.page == "Operadores":
        st.title("👥 Gestión de Operadores")
        try:
            # SE ENVÍA TOKEN POR PARAMS
            r = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics", headers=headers)
            if r.status_code == 200:
                usuarios = r.json()
                if usuarios:
                    # Formateo de tabla
                    data_list = [{"Email": k, "Rol": v.get('role', 'N/A')} for k, v in usuarios.items()]
                    st.dataframe(pd.DataFrame(data_list), use_container_width=True)
                else: st.info("No hay operadores registrados en la base de datos.")
            else: st.error("🛑 Acceso Denegado: Se requieren privilegios de Admin.")
        except Exception as e: st.error(f"Error al conectar con la base de datos: {e}")
        
    elif st.session_state.page == "Gobernanza":
        # --- ESTILOS CSS AVANZADOS ---
        st.markdown("""
            <style>
                .kpi-card { background: #161b22; padding: 20px; border-radius: 12px; border: 1px solid #30363d; }
                .risk-row { 
                    background: #0d1117; padding: 15px; border-radius: 10px; 
                    border: 1px solid #30363d; margin-bottom: 12px;
                    display: flex; justify-content: space-between; align-items: center;
                }
                .owner-badge { 
                    background: #21262d; color: #8b949e; padding: 2px 8px; 
                    border-radius: 10px; font-size: 11px; border: 1px solid #30363d;
                }
                .compliance-tag { font-size: 12px; color: #a78bfa; font-weight: bold; }
            </style>
        """, unsafe_allow_html=True)

        st.title("⚖️ Centro de Gobernanza y Estrategia")
        st.write("###")

        # --- FILA 1: KPIs CON SPARKLINE Y DESGLOSE ---
        col_a, col_b, col_c = st.columns(3)
        
        with col_a:
            st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
            st.metric("SECURITY SCORE", "92%", "+2.1%")
            # Sparkline de evolución (últimos 6 meses)
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
            # Desglose de cumplimiento que pidió el CTO
            st.markdown("""
                <div style="margin-top:10px;">
                    <span class="compliance-tag">GDPR: 85%</span> | 
                    <span class="compliance-tag">SOC2: 92%</span> | 
                    <span class="compliance-tag">ISO: 87%</span>
                </div>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        st.write("---")

        # --- FILA 2: MATRIZ DE RIESGOS (DISEÑO MOCKUP DEL CTO) ---
        col_left, col_right = st.columns([1.8, 1])

        with col_left:
            st.subheader("🛡️ Gestión de Activos y Riesgos")
            
            # Activo 1: ALTO
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

            # Activo 2: MEDIO
            st.markdown("""
                <div class="risk-row" style="border-left: 4px solid #d29922;">
                    <div>
                        <strong style="font-size:16px;">Base de Datos Usuarios</strong><br>
                        <span style="color:#8b949e; font-size:13px;">Mitigación: Encripción AES-256 Activa</span><br>
                        <span class="owner-badge">Dueño: @dba.team</span>
                    </div>
                    <div style="text-align:right;">
                        <span style="color:#238636; font-weight:bold; font-size:18px;">🟢</span><br>
                        <small style="color:#d29922;">MEDIO</small>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            # Activo 3: BAJO
            st.markdown("""
                <div class="risk-row" style="border-left: 4px solid #238636;">
                    <div>
                        <strong style="font-size:16px;">Nodo Vigilancia Central</strong><br>
                        <span style="color:#8b949e; font-size:13px;">Mitigación: Autenticación Token Bearer</span><br>
                        <span class="owner-badge">Dueño: @devops.team</span>
                    </div>
                    <div style="text-align:right;">
                        <span style="color:#238636; font-weight:bold; font-size:18px;">🟢</span><br>
                        <small style="color:#238636;">BAJO</small>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        with col_right:
            st.subheader("📋 Roadmap y Auditoría")
            with st.expander("📅 Próximos Hitos", expanded=True):
                st.write("**Auditoría Externa:** `2026-05-25`")
                st.write("**Revisión de Accesos:** `En 3 días`")
            
            st.write("###")
            # Botón de Reporte que genera el PDF (con lógica de simulación)
            if st.button("📥 Generar Reporte Ejecutivo PDF", use_container_width=True):
                with st.spinner('Compilando métricas y roadmap...'):
                    import time
                    time.sleep(2)
                    st.success("✅ Reporte 'Hyperion_Executive_Q2.pdf' listo para descarga.")
                    st.download_button("Click para descargar", "Contenido del PDF simulado", "Hyperion_Report.pdf")

        with col_right:
            st.subheader("📈 Auditoría y Reportes")
            with st.container(border=True):
                st.write("**Próxima Auditoría Interna:**")
                st.code("2026-05-25 (En 14 días)")
                
                st.write("**Reporte SOC2:**")
                st.progress(0.7)
                st.caption("Fase de recolección de evidencia: 70%")
                
                st.write("---")
                # Añadimos key="btn_reporte_gobernanza" para que sea único
                if st.button("📥 Generar Reporte Ejecutivo PDF", use_container_width=True, key="btn_reporte_gobernanza"):
                    with st.spinner('Compilando métricas y roadmap...'):
                        import time
                        time.sleep(2)
                        st.success("✅ Reporte 'Hyperion_Executive_Q2.pdf' listo para descarga.")
                        st.download_button(
                            label="Click para descargar", 
                            data="Contenido del PDF simulado", 
                            file_name="Hyperion_Report.pdf",
                            key="btn_download_final" # También le damos una key única al de descarga
                        )
            
    elif st.session_state.page == "AuditLogs":
        st.title("📜 Registros de Auditoría del Sistema")
        st.info("Historial de acciones críticas almacenadas en PostgreSQL.")

        try:
            r = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics", headers=headers)
            
            if r.status_code == 200:
                logs = r.json()
                if logs:
                    df_logs = pd.DataFrame(logs)
                    
                    # --- NUEVA SECCIÓN DE EXPORTACIÓN ---
                    col_search, col_exp = st.columns([2, 1])
                    
                    with col_search:
                        search = st.text_input("🔍 Filtrar logs:", placeholder="Ej: admin, login...")
                    
                    if search:
                        df_logs = df_logs[df_logs.apply(lambda row: search.lower() in row.astype(str).str.lower().values, axis=1)]

                    with col_exp:
                        st.write("📤 **Exportar Reporte**")
                        # Generar CSV en memoria
                        csv = df_logs.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="Descargar CSV",
                            data=csv,
                            file_name=f"audit_report_{time.strftime('%Y%m%d_%H%M')}.csv",
                            mime="text/csv",
                            use_container_width=True
                        )
                    # ------------------------------------

                    st.dataframe(
                        df_logs, 
                        use_container_width=True,
                        column_config={
                            "timestamp": "Fecha/Hora",
                            "actor": "Usuario",
                            "action": "Acción",
                            "target": "Detalle"
                        }
                    )
                    
                    st.caption(f"Mostrando {len(df_logs)} registros encontrados.")
                    
                else:
                    st.warning("No hay registros de auditoría en la base de datos.")
            else:
                st.error(f"🛑 Error {r.status_code}: No autorizado.")
        except Exception as e:
            st.error(f"🚨 Error de conexión: {e}")

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

        st.table(mock_data.style.map(color_level, subset=['Nivel']))