import streamlit as st
import requests
import os

backend_url = os.getenv("BACKEND_URL", "http://backend:8000")

st.title("Hyperion Dash")

if st.button('Verificar Conexión'):
    try:
        response = requests.get(f"{backend_url}/health")
        st.success(f"Backend dice: {response.json()}")
    except Exception as e:
        st.error(f"Error: {e}")