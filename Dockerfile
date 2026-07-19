# syntax=docker/dockerfile:1
# ---- build: install production deps only ----
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

# ---- runtime: slim, non-root, healthchecked ----
FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY package.json server.js ./
COPY lib ./lib
COPY public ./public
RUN chown -R node:node /app
USER node
EXPOSE 8080
# Stateless app: healthy = process up and /healthz 200. Orchestrators use this
# to gate traffic and restart unhealthy replicas.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["node", "server.js"]
