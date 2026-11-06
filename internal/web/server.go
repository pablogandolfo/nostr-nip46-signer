package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"nostr-nip46-signer/internal/keyvault"
	"nostr-nip46-signer/internal/nip46"
)

const (
	rateWindow = time.Minute
	maxEntries = 10000
)

type Server struct {
	mu        sync.RWMutex
	vault     *keyvault.Vault
	signer    *nip46.Signer
	relayURLs []string
	limiter   *RateLimiter

	// Autenticación de la API de administración.
	adminToken   string
	allowedHosts map[string]bool
}

type rateEntry struct {
	count     int
	resetTime time.Time
}

type RateLimiter struct {
	mu          sync.Mutex
	entries     map[string]*rateEntry
	lastCleanup time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		entries:     make(map[string]*rateEntry),
		lastCleanup: time.Now(),
	}
}

// Allow implementa una ventana fija por cliente y endpoint.
func (rl *RateLimiter) Allow(
	key string,
	limit int,
	window time.Duration,
) (bool, time.Duration) {

	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Limpieza periódica para evitar crecimiento indefinido.
	if now.Sub(rl.lastCleanup) >= 5*time.Minute ||
		len(rl.entries) >= maxEntries {

		for k, entry := range rl.entries {
			if !now.Before(entry.resetTime) {
				delete(rl.entries, k)
			}
		}

		rl.lastCleanup = now
	}

	entry, exists := rl.entries[key]

	if !exists || !now.Before(entry.resetTime) {
		// Protección adicional frente a agotamiento de memoria.
		if len(rl.entries) >= maxEntries {
			return false, window
		}

		rl.entries[key] = &rateEntry{
			count:     1,
			resetTime: now.Add(window),
		}

		return true, 0
	}

	if entry.count >= limit {
		return false, time.Until(entry.resetTime)
	}

	entry.count++

	return true, 0
}

// NewServer crea el servidor web.
//
// Token de administrador: se toma de la variable de entorno ADMIN_TOKEN;
// si no existe, se genera uno aleatorio de 256 bits en cada arranque.
//
// Hosts permitidos: loopback por defecto; se pueden añadir otros con
// ALLOWED_HOSTS (lista separada por comas, solo nombres, sin puerto).
func NewServer(relayURLs []string) *Server {
	token := os.Getenv("ADMIN_TOKEN")

	if token == "" {
		buf := make([]byte, 32)

		if _, err := rand.Read(buf); err != nil {
			// Sin aleatoriedad segura no se debe arrancar.
			panic("no secure randomness available")
		}

		token = hex.EncodeToString(buf)
	}

	hosts := map[string]bool{
		"127.0.0.1": true,
		"localhost": true,
		"::1":       true,
	}

	for _, h := range strings.Split(os.Getenv("ALLOWED_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))

		if h != "" {
			hosts[h] = true
		}
	}

	return &Server{
		relayURLs:    append([]string(nil), relayURLs...),
		limiter:      NewRateLimiter(),
		adminToken:   token,
		allowedHosts: hosts,
	}
}

// AdminToken devuelve el token vigente (para mostrarlo al operador al arrancar).
func (s *Server) AdminToken() string {
	return s.adminToken
}

// Handler registra la API y la interfaz web.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/key/import", s.importKey)
	mux.HandleFunc("POST /api/key/generate", s.generateKey)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/bunker", s.bunker)

	mux.Handle("GET /", http.FileServer(http.Dir("static")))

	// Orden (de fuera hacia dentro): cabeceras -> rate limit -> autenticación.
	// El rate limit queda por fuera de la autenticación para limitar
	// también los intentos de adivinar el token.
	return s.securityHeaders(s.rateLimit(s.guardAPI(mux)))
}

// Middleware de cabeceras de seguridad.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"form-action 'self'; "+
				"object-src 'none'",
		)

		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		next.ServeHTTP(w, r)
	})
}

// hostOnly extrae el nombre de host (sin puerto) en minúsculas.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}

	return strings.ToLower(strings.Trim(h, "[]"))
}

// Middleware de protección de la API:
//   - Host permitido (anti DNS rebinding)
//   - Origin igual al servidor (anti CSRF)
//   - Token de administrador (autenticación)
//   - Content-Type JSON en POST (obliga preflight en peticiones cruzadas)
func (s *Server) guardAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		if !s.allowedHosts[hostOnly(r.Host)] {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "forbidden",
			})
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)

			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "forbidden",
				})
				return
			}
		}

		got := r.Header.Get("X-Admin-Token")

		if subtle.ConstantTimeCompare(
			[]byte(got),
			[]byte(s.adminToken),
		) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "unauthorized",
			})
			return
		}

		if r.Method == http.MethodPost &&
			!strings.HasPrefix(
				strings.ToLower(r.Header.Get("Content-Type")),
				"application/json",
			) {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{
				"error": "content-type must be application/json",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Obtiene IP del socket directamente.
// No confía en X-Forwarded-For enviado por el cliente.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// Define límites específicos por endpoint.
func endpointLimit(r *http.Request) (int, time.Duration, bool) {
	switch {
	case r.Method == http.MethodPost &&
		r.URL.Path == "/api/key/import":
		return 5, rateWindow, true

	case r.Method == http.MethodPost &&
		r.URL.Path == "/api/key/generate":
		return 5, rateWindow, true

	case r.Method == http.MethodGet &&
		r.URL.Path == "/api/bunker":
		return 10, rateWindow, true

	case r.Method == http.MethodGet &&
		r.URL.Path == "/api/status":
		return 30, rateWindow, true

	default:
		return 0, 0, false
	}
}

// Middleware de limitación de solicitudes.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		limit, window, protected := endpointLimit(r)

		if !protected {
			next.ServeHTTP(w, r)
			return
		}

		key := clientIP(r) + "|" + r.Method + "|" + r.URL.Path

		allowed, retryAfter := s.limiter.Allow(
			key,
			limit,
			window,
		)

		if !allowed {
			seconds := int(retryAfter.Seconds()) + 1

			w.Header().Set(
				"Retry-After",
				strconv.Itoa(seconds),
			)

			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":       "rate limit exceeded",
				"retry_after": seconds,
			})

			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	data any,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

// Importación de una identidad Nostr.
func (s *Server) importKey(
	w http.ResponseWriter,
	r *http.Request,
) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var body struct {
		Nsec string `json:"nsec"`
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request",
		})
		return
	}

	// Rechazar contenido adicional después del JSON.
	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	body.Nsec = strings.TrimSpace(body.Nsec)

	if body.Nsec == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing nsec",
		})
		return
	}

	vault, err := keyvault.New(body.Nsec)

	// Reducir la permanencia de la referencia a la clave
	// dentro del objeto de entrada (no garantiza borrado en memoria).
	body.Nsec = ""

	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid private key",
		})
		return
	}

	// La clave pública se lee antes de instalar el vault, porque
	// instalarlo puede cerrar el anterior si hay otra operación concurrente.
	pubkey, err := vault.PublicKey()

	if err != nil {
		vault.Close()

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "vault unavailable",
		})
		return
	}

	if err := s.installVault(vault); err != nil {
		vault.Close()

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to initialize signer",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "imported",
		"pubkey": pubkey,
	})
}

// Generación de una identidad de prueba.
func (s *Server) generateKey(
	w http.ResponseWriter,
	r *http.Request,
) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	defer r.Body.Close()

	vault, err := keyvault.Generate()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate key",
		})
		return
	}

	pubkey, err := vault.PublicKey()

	if err != nil {
		vault.Close()

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "vault unavailable",
		})
		return
	}

	if err := s.installVault(vault); err != nil {
		vault.Close()

		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to initialize signer",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "generated",
		"pubkey": pubkey,
	})
}

// Instala la identidad y arranca el transporte NIP-46.
//
// La conexión a los relays (Start) se hace SIN mantener el mutex, para no
// bloquear /api/status ni /api/bunker mientras se establecen las conexiones.
func (s *Server) installVault(vault *keyvault.Vault) error {
	newSigner := nip46.NewSigner(vault, s.relayURLs)

	if err := newSigner.Start(); err != nil {
		newSigner.Close()
		return err
	}

	// Solo se sustituye la identidad anterior cuando el nuevo signer
	// se inicializó correctamente.
	s.mu.Lock()
	oldSigner := s.signer
	oldVault := s.vault

	s.signer = newSigner
	s.vault = vault
	s.mu.Unlock()

	if oldSigner != nil {
		oldSigner.Close()
	}

	if oldVault != nil {
		oldVault.Close()
	}

	return nil
}

// Consulta de estado.
func (s *Server) status(
	w http.ResponseWriter,
	r *http.Request,
) {
	s.mu.RLock()

	vault := s.vault
	relays := append([]string(nil), s.relayURLs...)

	if vault == nil {
		s.mu.RUnlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"initialized": false,
		})
		return
	}

	pubkey, err := vault.PublicKey()

	s.mu.RUnlock()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "vault unavailable",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": true,
		"pubkey":      pubkey,
		"relays":      relays,
	})
}

// Generación de URI bunker.
func (s *Server) bunker(
	w http.ResponseWriter,
	r *http.Request,
) {
	s.mu.RLock()
	signer := s.signer
	s.mu.RUnlock()

	if signer == nil {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "signer not initialized",
		})
		return
	}

	uri, err := signer.GenerateBunkerURI()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate bunker URI",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"bunker": uri,
	})
}

// Cierre controlado de los recursos.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.signer != nil {
		s.signer.Close()
		s.signer = nil
	}

	if s.vault != nil {
		s.vault.Close()
		s.vault = nil
	}
}
