import streamlit as st
import requests
import os

BACKEND_INTERNAL = os.getenv("BACKEND_URL", "http://backend:8000")
BACKEND_EXTERNAL = "http://localhost:8000"

st.set_page_config(page_title="Hyperion Ops", layout="wide")

if "token" not in st.session_state: st.session_state.token = None
if "requires_2fa" not in st.session_state: st.session_state.requires_2fa = False
if "temp_email" not in st.session_state: st.session_state.temp_email = ""

st.sidebar.title("🛡️ Hyperion System")
menu = ["Acceso", "Configurar 2FA", "Dashboard de Auditoría"]
choice = st.sidebar.selectbox("Navegación", menu)

if choice == "Acceso":
    st.subheader("🔑 Control de Acceso")
    if st.session_state.requires_2fa:
        otp = st.text_input("OTP (123456)", max_chars=6)
        if st.button("Verificar"):
            res = requests.post(f"{BACKEND_INTERNAL}/auth/login/verify-2fa", json={"email": st.session_state.temp_email, "code": otp})
            if res.status_code == 200:
                st.session_state.token = res.json()["access_token"]
                st.session_state.requires_2fa = False
                st.success("Acceso Concedido")
                st.rerun()
    elif not st.session_state.token:
        t1, t2 = st.tabs(["Login", "Registro"])
        with t1:
            e = st.text_input("Usuario")
            p = st.text_input("Clave", type="password")
            if st.button("Entrar"):
                res = requests.post(f"{BACKEND_INTERNAL}/auth/login", data={"username": e, "password": p})
                if res.status_code == 200:
                    st.session_state.requires_2fa, st.session_state.temp_email = True, e
                    st.rerun()
                else: st.error(res.json().get("detail"))
        with t2:
            re = st.text_input("Nuevo Operador")
            rp = st.text_input("Nueva Clave", type="password")
            if st.button("Registrar"):
                requests.post(f"{BACKEND_INTERNAL}/auth/register", json={"email": re, "password": rp})
                st.success("Registrado")
    else:
        st.success(f"Sesión activa: {st.session_state.temp_email}")
        if st.button("Cerrar Sesión"):
            st.session_state.token = None
            st.rerun()

elif choice == "Dashboard de Auditoría":
    if not st.session_state.token:
        st.error("🚫 Bloqueado. Requiere Autenticación.")
    else:
        # Enviamos el token en la URL
        url = f"{BACKEND_EXTERNAL}/dashboard?token={st.session_state.token}"
        st.markdown(f'<a href="{url}" target="_blank"><button style="width:100%;background-color:#2563eb;color:white;padding:15px;border:none;border-radius:10px;cursor:pointer;font-weight:bold;">🌐 ABRIR PANEL EN VIVO</button></a>', unsafe_allow_html=True)

elif choice == "Configurar 2FA":
    st.info("⚙️ Configuración de Seguridad")