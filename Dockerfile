# ---------------------------------------------------------------------------
# AegisSOC — production image
# Stage 1 builds the frontend (vite) and bundles the server (esbuild).
# Stage 2 is a lean runtime: prod dependencies + the dist output only.
# ---------------------------------------------------------------------------

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /app

# Prod dependencies only — the server bundles Vite as a dev-only dynamic import.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY --from=build /app/dist ./dist

EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

USER node
CMD ["node", "dist/server.cjs"]