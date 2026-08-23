# Multi-stage build for KyPasswords Server

# Stage 1: Build React Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Go Backend Binary
FROM golang:1.27-alpine AS backend-builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /kypassword-server ./cmd/server/main.go

# Stage 3: Minimal Production Image
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -S kypassword && adduser -S kypassword -G kypassword \
    && mkdir -p /kypassword/data /kypassword/config /app/frontend/dist \
    && chown -R kypassword:kypassword /kypassword /app

WORKDIR /app
COPY --from=backend-builder /kypassword-server /usr/local/bin/kypassword-server
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

USER kypassword:kypassword
ENV PORT=5877 \
    DATA_DIR=/kypassword/data \
    CONFIG_DIR=/kypassword/config \
    WEB_DIR=/app/frontend/dist

VOLUME ["/kypassword/data", "/kypassword/config"]
EXPOSE 5877

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5877/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/kypassword-server"]
