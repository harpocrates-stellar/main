FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .

# Accept Vite environment variables at build time so the static bundle is
# compiled with the correct runtime values baked in.  All four are optional so
# the image still builds successfully for local development without them.
ARG VITE_API_BASE
ARG VITE_STELLAR_RPC_URL
ARG VITE_STELLAR_READONLY_SOURCE
ARG VITE_HARPOCRATES_REGISTRY_ID

ENV VITE_API_BASE=$VITE_API_BASE \
    VITE_STELLAR_RPC_URL=$VITE_STELLAR_RPC_URL \
    VITE_STELLAR_READONLY_SOURCE=$VITE_STELLAR_READONLY_SOURCE \
    VITE_HARPOCRATES_REGISTRY_ID=$VITE_HARPOCRATES_REGISTRY_ID

RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

# Configure nginx to run as unprivileged non-root user (nginx: UID/GID 101):
# 1. Update PID path to /tmp/nginx.pid where unprivileged user has write access
# 2. Comment out the 'user' directive to prevent runtime master-process warnings
# 3. Grant ownership on runtime directories (/var/cache/nginx, /var/log/nginx, /etc/nginx/conf.d, web root)
RUN sed -i 's|^user\s\+nginx;|# user nginx;|' /etc/nginx/nginx.conf \
    && sed -i 's|/var/run/nginx.pid|/tmp/nginx.pid|g; s|/run/nginx.pid|/tmp/nginx.pid|g' /etc/nginx/nginx.conf \
    && (grep -q "pid /tmp/nginx.pid;" /etc/nginx/nginx.conf || sed -i '1i pid /tmp/nginx.pid;' /etc/nginx/nginx.conf) \
    && touch /tmp/nginx.pid \
    && chown -R nginx:nginx /tmp/nginx.pid /var/cache/nginx /var/log/nginx /etc/nginx/conf.d /usr/share/nginx/html \
    && chmod -R 755 /usr/share/nginx/html

USER nginx:nginx

EXPOSE 8080

# Liveness probe: nginx must serve the SPA root. wget ships with nginx:alpine.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:8080/ || exit 1
