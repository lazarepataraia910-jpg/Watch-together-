# Container for hosts that build from a Dockerfile (Northflank). Render ignores this file.
FROM node:22-slim

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .
# The server writes data/ (JSON fallback, local session key); the unprivileged user must own it.
RUN mkdir -p data && chown node:node data

# Northflank routes public traffic to this port (set the same port on the service).
ENV PORT=3000
EXPOSE 3000

USER node
CMD ["node", "server.js"]
