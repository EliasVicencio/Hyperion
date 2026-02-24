#!/bin/bash
echo "🛡️ Iniciando Instalación Universal de Hyperion..."

# 1. Crear .env si no existe
if [ ! -f .env ]; then
    echo "📝 Creando archivo .env desde la plantilla..."
    cp .env.example .env
    echo "⚠️ ADVERTENCIA: Edita el archivo .env con tus credenciales reales."
fi

# 2. Levantar la infraestructura
echo "🚀 Levantando contenedores..."
docker-compose up -d --build

echo "✅ Hyperion está corriendo en:"
echo "   - Dashboard: http://localhost:8501"
echo "   - API/Docs: http://localhost:8000/docs"