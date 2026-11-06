# Evidencias de Verificación y Seguridad

Este documento recopila las pruebas de ejecución y validación de los controles de seguridad implementados en el **Nostr Remote Signer MVP**, incluyendo la protección de la API mediante token de administración, validación de host/origen y cabeceras HTTP restrictivas.

---

## 1. Gestión del Token de Administración

Al iniciar la aplicación localmente sin establecer la variable de entorno `ADMIN_TOKEN`, el servidor genera automáticamente un token seguro de 32 bytes en memoria y lo expone en la consola para uso del operador:

```text
2026/11/06 09:45:00 Admin token (pégalo en la interfaz): 35db10e23b0042445568a217429fb805c97291de033657e962b1b29d609fe1fb
2026/11/06 09:45:00 Remote Signer listening on http://127.0.0.1:8080
```

En entornos de producción o contenedores, el token puede inyectarse mediante la variable de entorno `ADMIN_TOKEN`. En ese caso, el log omite la impresión del valor para evitar fugas en recolectores de logs:

```bash
export ADMIN_TOKEN="secreto_de_produccion"
go run ./cmd/main.go
# Log output: "Admin token cargado desde ADMIN_TOKEN"
```

---

## 2. Pruebas de Verificación HTTP (curl)

Las siguientes ejecuciones reproducen la verificación de los controles del middleware `guardAPI` y las cabeceras HTTP de seguridad.

### 2.1. Intentar acceder a la API sin token (Rechazo 401 Unauthorized)

```bash
curl -i http://127.0.0.1:8080/api/status
```

**Respuesta recibida:**
```http
HTTP/1.1 401 Unauthorized
Cache-Control: no-store
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'
Content-Type: application/json
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Date: Fri, 06 Nov 2026 12:44:52 GMT
Content-Length: 25

{"error":"unauthorized"}
```

---

### 2.2. Acceder a la API con token válido (Respuesta 200 OK)

```bash
curl -i -H "X-Admin-Token: 35db10e23b0042445568a217429fb805c97291de033657e962b1b29d609fe1fb" \
  http://127.0.0.1:8080/api/status
```

**Respuesta recibida:**
```http
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'
Content-Type: application/json
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Date: Fri, 06 Nov 2026 12:45:52 GMT
Content-Length: 22

{"initialized":false}
```

---

### 2.3. Protección contra origen malicioso / Cross-Origin (Rechazo 403 Forbidden)

```bash
curl -i -H "X-Admin-Token: 35db10e23b0042445568a217429fb805c97291de033657e962b1b29d609fe1fb" \
  -H "Origin: https://evil.example" \
  http://127.0.0.1:8080/api/status
```

**Respuesta esperada:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error":"forbidden"}
```

---

### 2.4. Protección DNS Rebinding / Host Header Spoofing (Rechazo 403 Forbidden)

```bash
curl -i -H "X-Admin-Token: 35db10e23b0042445568a217429fb805c97291de033657e962b1b29d609fe1fb" \
  -H "Host: evil.example" \
  http://127.0.0.1:8080/api/status
```

**Respuesta esperada:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error":"forbidden"}
```

---

### 2.5. Validación de Content-Type en peticiones POST (Rechazo 415 Unsupported Media Type)

```bash
curl -i -X POST \
  -H "X-Admin-Token: 35db10e23b0042445568a217429fb805c97291de033657e962b1b29d609fe1fb" \
  -H "Content-Type: text/plain" \
  http://127.0.0.1:8080/api/key/generate
```

**Respuesta esperada:**
```http
HTTP/1.1 415 Unsupported Media Type
Content-Type: application/json

{"error":"content-type must be application/json"}
```

---

## 3. Resumen de Cabeceras de Seguridad HTTP Verificadas

Todas las respuestas del servidor integran las siguientes cabeceras para mitigar vulnerabilidades web comunes:

- `Cache-Control: no-store`: Impide el almacenamiento en caché de estados sensibles o tokens.
- `X-Frame-Options: DENY`: Mitiga ataques de Clickjacking impidiendo el renderizado en `<iframe>`.
- `X-Content-Type-Options: nosniff`: Evita la interpretación incorrecta de tipos MIME por parte del navegador.
- `Referrer-Policy: no-referrer`: Previene la fuga de rutas internas en cabeceras de navegación.
- `Content-Security-Policy`: Aplica directivas estrictas (`frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`, `object-src 'none'`).