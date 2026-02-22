import streamlit as st
import requests
import os

# 1. Esta URL la usa el CÓDIGO de Streamlit para hablar con el Backend (Interno Docker)
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# 2. Esta URL la usa TU NAVEGADOR (Chrome/Edge) para abrir el Dashboard (Externo)
BACKEND_URL_EXTERNA = "http://localhost:8000" 

st.set_page_config(page_title="Hyperion Security", page_icon="🛡️", layout="centered")

# --- ESTADO DE SESIÓN ---
if "token" not in st.session_state:
    st.session_state.token = None
if "requires_2fa" not in st.session_state:
    st.session_state.requires_2fa = False
if "temp_email" not in st.session_state:
    st.session_state.temp_email = None

st.title("🛡️ Sistema Hyperion")
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/702/702003.png", width=100)
menu = ["Acceso", "Configurar 2FA", "Dashboard de Auditoría"]
choice = st.sidebar.selectbox("Navegación", menu)

# --- MÓDULO 1: ACCESO (LOGIN Y REGISTRO) ---
if choice == "Acceso":
    st.info("Bienvenido. Inicie sesión o cree una cuenta nueva para acceder a la red.")
    
    # Creamos pestañas visuales para que no se pierda
    tab_login, tab_register = st.tabs(["🔑 Iniciar Sesión", "📝 Crear Cuenta Nueva"])

    with tab_register:
        st.subheader("Formulario de Registro")
        with st.form("registro_form"):
            reg_email = st.text_input("Correo Electrónico")
            reg_pass = st.text_input("Contraseña", type="password")
            reg_role = st.selectbox("Rol", ["employee", "admin", "guest"])
            submit_reg = st.form_submit_button("Registrar Usuario")
            
            if submit_reg:
                if reg_email and reg_pass:
                    res = requests.post(f"{BACKEND_URL}/auth/register", 
                                       json={"email": reg_email, "password": reg_pass, "role": reg_role})
                    if res.status_code == 200:
                        st.success("✅ ¡Cuenta creada con éxito! Ahora puedes ir a la pestaña de 'Iniciar Sesión'.")
                    else:
                        st.error(f"❌ Error: {res.json().get('detail')}")
                else:
                    st.warning("Por favor rellena todos los campos.")

    with tab_login:
        if not st.session_state.requires_2fa:
            st.subheader("Login de Seguridad")
            with st.form("login_form"):
                email = st.text_input("Email")
                password = st.text_input("Contraseña", type="password")
                submit_log = st.form_submit_button("Entrar")
                
                if submit_log:
                    res = requests.post(f"{BACKEND_URL}/auth/login", data={"username": email, "password": password})
                    if res.status_code == 200:
                        data = res.json()
                        if data.get("requires_2fa"):
                            st.session_state.requires_2fa = True
                            st.session_state.temp_email = email
                            st.rerun()
                        else:
                            st.session_state.token = data["access_token"]
                            st.success("✅ Acceso concedido")
                    else:
                        st.error("Credenciales incorrectas")
        else:
            # PANTALLA DE SEGUNDO FACTOR
            st.warning(f"🔒 Verificación 2FA: {st.session_state.temp_email}")
            otp_code = st.text_input("Introduce el código de 6 dígitos de tu móvil", maxlength=6)
            if st.button("Verificar Identidad"):
                res = requests.post(f"{BACKEND_URL}/auth/login/verify-2fa", 
                                   json={"email": st.session_state.temp_email, "code": otp_code})
                if res.status_code == 200:
                    st.session_state.token = res.json()["access_token"]
                    st.session_state.requires_2fa = False
                    st.success("✅ Verificación exitosa. Bienvenido al sistema.")
                else:
                    st.error("Código 2FA incorrecto o expirado")

# --- MÓDULO 2: CONFIGURAR 2FA (IGUAL QUE ANTES) ---
elif choice == "Configurar 2FA":
    if not st.session_state.token:
        st.error("❌ Área Restringida. Debes iniciar sesión primero.")
    else:
        st.subheader("🔐 Panel de Seguridad 2FA")
        # ... (aquí va el código de setup y activate que ya teníamos)
        st.write("Sigue los pasos para blindar tu cuenta.")
        if st.button("Generar Secreto"):
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            res = requests.post(f"{BACKEND_URL}/auth/2fa/setup", headers=headers)
            setup_data = res.json()
            
            # En lugar de st.json(res.json()), ponemos algo más visual:
            st.success("✅ ¡Secreto generado con éxito!")
            st.code(setup_data['secret'], language=None)
            st.info("👆 Copia este código y añádelo manualmente en tu app Google Authenticator.")

# --- MÓDULO 3: DASHBOARD ---
elif choice == "Dashboard de Auditoría":
    st.header("📊 Centro de Operaciones")

    # Si no hay token, mostramos el error de área restringida (Imagen 4)
    if "token" not in st.session_state or st.session_state.token is None:
        st.error("❌ **Área Restringida. Debes iniciar sesión primero.**")
        st.info("El acceso a las métricas de red requiere un Token de Auditor activo.")
    else:
        # Si hay token, mostramos la interfaz nivel 2FA (Imagen 2)
        st.success("✅ **Credenciales de Auditoría Validadas**")
        
        st.subheader("🚀 Acceso al Panel de Control")
        st.write("Sigue los pasos para abrir la consola de monitoreo:")

        # URL SEGURA CON TOKEN (Para evitar el error de la imagen 8)
        url_segura = f"http://localhost:8000/dashboard?token={st.session_state.token}"

        # Contenedor de seguridad idéntico al del 2FA
        st.markdown(f"""
            <div style="
                background-color: #111827; 
                padding: 25px; 
                border-radius: 12px; 
                border: 1px solid #374151; 
                text-align: center;
                margin-top: 10px;
            ">
                <p style="color: #9CA3AF; font-size: 14px; margin-bottom: 20px;">
                    Cifrado de sesión activo: <span style="color: #60A5FA;">RSA-4096 / JWT</span>
                </p>
                <a href="{url_segura}" target="_blank" style="text-decoration: none;">
                    <div style="
                        background-color: #1F2937; 
                        color: #60A5FA; 
                        padding: 15px; 
                        border-radius: 8px; 
                        border: 1px solid #4B5563; 
                        cursor: pointer; 
                        font-weight: bold;
                        transition: 0.3s;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    ">
                        🛰️ Lanzar Dashboard de Seguridad
                    </div>
                </a>
            </div>
        """, unsafe_allow_html=True)

        st.divider()
        st.caption("Acceso vinculado al ID de sesión: " + str(st.session_state.token[:10]) + "...")