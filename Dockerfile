# --- ETAPA 1: Compilación de Go ---
FROM golang:1.27.3-alpine AS builder

WORKDIR /app

# Copiar dependencias y código fuente
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compilar un binario estático optimizado
RUN CGO_ENABLED=0 GOOS=linux go build -o nip46-signer ./cmd/main.go

# --- ETAPA 2: Imagen Final Ultraliviana ---
FROM alpine:latest

WORKDIR /app

# Copiar el binario compilado y los archivos estáticos (frontend)
COPY --from=builder /app/nip46-signer /app/nip46-signer
COPY --from=builder /app/static /app/static

# Forzar escucha en todas las interfaces dentro del contenedor
ENV HTTP_ADDR=:8080

# Exponer el puerto de la aplicación
EXPOSE 8080

# Ejecutar el binario
CMD ["./nip46-signer"]