import streamlit as st
import requests
import os

BACKEND_INTERNAL = os.getenv("BACKEND_URL", "http://backend:8000")
BACKEND_EXTERNAL = "http://localhost:8000"

# --- NUEVA CONSTANTE PARA TOTP ---
TOTP_SECRET = "JBSWY3DPEHPK3PXP" 

st.set_page_config(page_title="Hyperion Ops", layout="wide")

# Inicialización de estados
if "token" not in st.session_state: st.session_state.token = None
if "requires_2fa" not in st.session_state: st.session_state.requires_2fa = False
if "temp_email" not in st.session_state: st.session_state.temp_email = ""

st.sidebar.title("🛡️ Hyperion System")
menu = ["Acceso", "Configurar 2FA", "Dashboard de Auditoría", "Central de Vigilancia"]
choice = st.sidebar.selectbox("Navegación", menu)

if choice == "Acceso":
    # --- CENTRADO DEL FORMULARIO ---
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("<h1 style='text-align: center;'>🔐 Control de Acceso</h1>", unsafe_allow_html=True)
        
        if st.session_state.requires_2fa:
            st.warning("Verificación de Dos Pasos Requerida")
            
            # --- SECCIÓN DE VINCULACIÓN ACTUALIZADA ---
            with st.expander("📱 Vincular Google Authenticator / Authy", expanded=True):
                st.write("Escanea este QR con tu aplicación de seguridad:")
                # Usamos la constante TOTP_SECRET para que coincida con el backend
                qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=otpauth://totp/Hyperion:{st.session_state.temp_email}?secret={TOTP_SECRET}&issuer=Hyperion"
                st.image(qr_url)
                st.code(f"Código Secreto: {TOTP_SECRET}", language="text")
                st.caption("Si no puedes escanear el QR, ingresa el código secreto manualmente en la app.")
            
            # Texto actualizado para indicar que acepta ambos
            otp = st.text_input("Ingresa el código de tu App (o auxilio: 123456)", max_chars=6)
            
            if st.button("Verificar y Entrar", use_container_width=True):
                res = requests.post(f"{BACKEND_INTERNAL}/auth/login/verify-2fa", json={"email": st.session_state.temp_email, "code": otp})
                if res.status_code == 200:
                    st.session_state.token = res.json()["access_token"]
                    st.session_state.requires_2fa = False
                    st.success("Acceso Concedido")
                    st.rerun()
                else:
                    st.error("Código OTP incorrecto o expirado")

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
                        st.error(res.json().get("detail", "Error de conexión"))
            
            with tab_reg:
                new_user = st.text_input("Nuevo Usuario")
                new_pass = st.text_input("Nueva Clave", type="password")
                if st.button("Crear Cuenta", use_container_width=True):
                    res = requests.post(f"{BACKEND_INTERNAL}/auth/register", json={"email": new_user, "password": new_pass})
                    if res.status_code == 200:
                        st.success("Operador registrado con éxito")
                    else:
                        st.error("Error al registrar")
        else:
            st.balloons()
            st.success(f"Sesión activa como: {st.session_state.temp_email}")
            if st.button("Cerrar Sesión Segura", use_container_width=True):
                st.session_state.token = None
                st.rerun()

elif choice == "Dashboard de Auditoría":
    st.markdown("<h1 style='text-align: center;'>🛡️ Dashboard de Seguridad</h1>", unsafe_allow_html=True)
    
    # --- NUEVA DESCRIPCIÓN SOLICITADA ---
    st.markdown("""
        <p style='text-align: center; color: #94a3b8; font-size: 1.1rem; margin-bottom: 2rem;'>
        En este apartado podrás ingresar al dashboard completo para gestionar la seguridad de tu empresa.
        </p>
    """, unsafe_allow_html=True)
    
    if not st.session_state.token:
        st.error("🚫 Acceso restringido. Por favor, inicie sesión.")
    else:
        # --- BOTÓN REDISEÑADO (MÁS PEQUEÑO Y ESTILIZADO) ---
        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1]) # Columnas para centrar y achicar
        
        with col_btn2:
            url = f"{BACKEND_EXTERNAL}/dashboard?token={st.session_state.token}"
            st.markdown(f'''
                <a href="{url}" target="_blank" style="text-decoration: none;">
                    <button style="
                        width: 100%;
                        background-color: #2563eb;
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: 600;
                        font-size: 14px;
                        transition: background-color 0.3s;
                    " onmouseover="this.style.backgroundColor='#1d4ed8'" onmouseout="this.style.backgroundColor='#2563eb'">
                        INGRESAR AL PANEL
                    </button>
                </a>
            ''', unsafe_allow_html=True)


# Central de vigilancia
elif choice == "Central de Vigilancia":
    st.markdown("<h1 style='text-align: center;'>👁️ Hyperion: Central de Vigilancia</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #94a3b8;'>Monitor de latencia y rendimiento de recursos en tiempo real.</p>", unsafe_allow_html=True)

    if not st.session_state.token:
        st.error("🚫 Acceso restringido. Por favor, inicie sesión.")
    else:
        # Contenedores para métricas en tiempo real
        col_m1, col_m2, col_m3 = st.columns(3)
        cpu_stat = col_m1.empty()
        ram_stat = col_m2.empty()
        disk_stat = col_m3.empty()
        
        chart_container = st.empty()
        
        # Simulación de historial para el gráfico (usando session_state para que persista)
        if "metrics_history" not in st.session_state:
            st.session_state.metrics_history = {"cpu": [], "ram": []}

        # Loop de actualización en tiempo real
        for _ in range(20): # Se actualizará 20 veces antes de detenerse (o usa while True)
            try:
                res = requests.get(f"{BACKEND_INTERNAL}/api/system-metrics?token={st.session_state.token}")
                data = res.json()
                
                # Actualizar indicadores numéricos
                cpu_stat.metric("Uso de CPU", f"{data['cpu']}%")
                ram_stat.metric("Memoria RAM", f"{data['ram']}%")
                disk_stat.metric("Espacio en Disco", f"{data['disk']}%")
                
                # Actualizar historial para el gráfico
                st.session_state.metrics_history["cpu"].append(data['cpu'])
                st.session_state.metrics_history["ram"].append(data['ram'])
                
                # Mantener solo los últimos 30 puntos
                if len(st.session_state.metrics_history["cpu"]) > 30:
                    st.session_state.metrics_history["cpu"].pop(0)
                    st.session_state.metrics_history["ram"].pop(0)
                
                # Dibujar gráfico
                chart_container.line_chart(st.session_state.metrics_history)
                
                import time
                time.sleep(2) # Actualización cada 2 segundos
            except:
                st.error("Conexión perdida con el motor de vigilancia.")
                break