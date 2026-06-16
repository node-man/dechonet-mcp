# Dockerfile for Glama (https://glama.ai/mcp/servers) build & introspection check.
# The MCP server speaks stdio, so Glama runs the image and connects over
# stdin/stdout — it only needs the server to start and answer an introspection
# (initialize / tools/list) request. No ports are exposed.

# --- build stage: compile TypeScript -> build/ ---
FROM node:20-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# --- runtime stage: prod deps + compiled output ---
FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder /app/build ./build
COPY README.md ./
# stdio transport — Glama connects via stdin/stdout, no EXPOSE needed.
ENTRYPOINT ["node", "build/index.js"]
