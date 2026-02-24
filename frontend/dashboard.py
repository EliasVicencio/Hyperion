import streamlit as st
import requests
import os

# Docker usará 'backend' como nombre de host
backend_url = os.getenv("BACKEND_URL", "http://backend:8000")

st.title("🛡️ Hyperion Dash")

if st.button('Verificar Conexión'):
    try:
        # Aquí es donde llamamos al nuevo endpoint /health
        response = requests.get(f"{backend_url}/health")
        if response.status_code == 200:
            st.success(f"✅ ¡Éxito! {response.json()['message']}")
        else:
            st.error(f"❌ El backend respondió con error {response.status_code}")
    except Exception as e:
        st.error(f"⚠️ No se pudo conectar al backend: {e}")