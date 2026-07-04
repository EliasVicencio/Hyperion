# --- ETAPA 1: Compilación del código ---
FROM node:20-alpine AS build

WORKDIR /app

# Copiar manifiestos e instalar dependencias aprovechando la caché de capas de Docker
COPY package*.json ./
RUN npm install

# Copiar el resto del código y compilar para producción
COPY . .
RUN npm run build

# --- ETAPA 2: Servidor web de producción ligero ---
FROM nginx:1.25-alpine

# Copiar los archivos compilados desde la etapa anterior al directorio público de Nginx
COPY --from=build /app/dist /usr/share/nginx/html

# Copiar configuración personalizada de Nginx (para manejar rutas de React SPA)
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]