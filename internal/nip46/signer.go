package nip46

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"

	"nostr-nip46-signer/internal/keyvault"
)

const (
	NIP46Kind      = 24133
	LoginEventKind = 22242
)

var (
	ErrUnauthorized = errors.New("unauthorized NIP-46 client")
	ErrInvalidEvent = errors.New("invalid NIP-46 event")
	ErrPairing      = errors.New("invalid or expired pairing secret")
	ErrPermission   = errors.New("requested permission not granted")
)

type Request struct {
	ID     string   `json:"id"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

type Response struct {
	ID     string `json:"id"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Session struct {
	ClientPubKey string
	Permissions  map[string]bool
	CreatedAt    time.Time
}

type Signer struct {
	mu sync.RWMutex

	vault     *keyvault.Vault
	relays    []*nostr.Relay
	relayURLs []string

	sessions map[string]*Session
	seen     map[string]time.Time

	pairingSecret string
	pairingExpiry time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

type cipherScheme int

const (
	schemeNIP44 cipherScheme = iota
	schemeNIP04
)

func (s *Signer) decrypt(clientPubKey, content string) (string, cipherScheme, error) {
	if strings.Contains(content, "?iv=") { // formato NIP-04
		secret, err := s.vault.NIP04SharedSecret(clientPubKey)
		if err != nil {
			return "", schemeNIP04, err
		}
		pt, err := nip04.Decrypt(content, secret)
		return pt, schemeNIP04, err
	}

	key, err := s.vault.NIP44ConversationKey(clientPubKey)
	if err != nil {
		return "", schemeNIP44, err
	}
	pt, err := nip44.Decrypt(content, key)
	return pt, schemeNIP44, err
}

func (s *Signer) encrypt(clientPubKey, plaintext string, sch cipherScheme) (string, error) {
	if sch == schemeNIP04 {
		secret, err := s.vault.NIP04SharedSecret(clientPubKey)
		if err != nil {
			return "", err
		}
		return nip04.Encrypt(plaintext, secret)
	}

	key, err := s.vault.NIP44ConversationKey(clientPubKey)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, key)
}

const HTTPAuthKind = 27235 // NIP-98, el que pide Stacker News

var allowedKinds = map[int]bool{
	LoginEventKind: true,
	HTTPAuthKind:   true,
}

// Dominios para los que este signer firma autenticación HTTP.
var allowedAuthHosts = map[string]bool{
	"stacker.news": true,
}

const maxEventSkew = 2 * time.Minute

func tagValue(tags nostr.Tags, name string) string {
	for _, t := range tags {
		if len(t) >= 2 && t[0] == name {
			return t[1]
		}
	}
	return ""
}

// validateHTTPAuth verifica que un evento 27235 sea para un dominio permitido.
func validateHTTPAuth(ev *nostr.Event) error {
	u, err := url.Parse(tagValue(ev.Tags, "u"))
	if err != nil || u.Scheme != "https" || !allowedAuthHosts[strings.ToLower(u.Hostname())] {
		log.Printf("[NIP46] sign_event rejected: u host not allowed")
		return ErrPermission
	}

	method := strings.ToUpper(tagValue(ev.Tags, "method"))
	if method != "GET" && method != "POST" {
		log.Printf("[NIP46] sign_event rejected: method=%q", method)
		return ErrPermission
	}

	challenge := tagValue(ev.Tags, "challenge")
	if challenge == "" || len(challenge) > 256 {
		return ErrInvalidEvent
	}

	return nil
}

func NewSigner(vault *keyvault.Vault, relayURLs []string) *Signer {
	ctx, cancel := context.WithCancel(context.Background())

	return &Signer{
		vault:     vault,
		relayURLs: relayURLs,
		sessions:  make(map[string]*Session),
		seen:      make(map[string]time.Time),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (s *Signer) alreadySeen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, t := range s.seen { // limpieza simple
		if now.Sub(t) > 5*time.Minute {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[id]; ok {
		return true
	}
	s.seen[id] = now
	return false
}

// GeneratePairingSecret genera un secreto criptográficamente aleatorio.
func GeneratePairingSecret() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil

}

// GenerateBunkerURI genera una URI bunker://.
// GenerateBunkerURI genera una URI bunker:// compatible con Stacker News.
func (s *Signer) GenerateBunkerURI() (string, error) {
	pubkey, err := s.vault.PublicKey()
	if err != nil {
		return "", err
	}

	secret, err := GeneratePairingSecret()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.pairingSecret = secret
	s.pairingExpiry = time.Now().Add(10 * time.Minute)
	s.mu.Unlock()

	u := &url.URL{
		Scheme: "bunker",
		Host:   pubkey,
	}

	q := url.Values{}

	// Usar únicamente el primer relay configurado para evitar bugs de parsing en el cliente de Stacker News
	if len(s.relayURLs) > 0 {
		q.Set("relay", s.relayURLs[0])
	}

	q.Set("secret", secret)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// Start conecta a los relays y procesa eventos NIP-46.
func (s *Signer) Start() error {
	pubkey, err := s.vault.PublicKey()
	if err != nil {
		return err
	}

	if len(s.relayURLs) == 0 {
		return errors.New("no relays configured")
	}

	connected := 0

	for _, relayURL := range s.relayURLs {
		relay, err := nostr.RelayConnect(s.ctx, relayURL)
		if err != nil {
			log.Printf("[NIP46] Relay connection failed: %s: %v", relayURL, err)
			continue
		}

		since := nostr.Now() - 60 // margen de 60 s por desfase de reloj

		filter := nostr.Filter{
			Kinds: []int{NIP46Kind},
			Since: &since,
			Tags: nostr.TagMap{
				"p": []string{pubkey},
			},
		}

		sub, err := relay.Subscribe(s.ctx, nostr.Filters{filter})
		if err != nil {
			log.Printf("[NIP46] Subscription failed: %s: %v", relayURL, err)
			_ = relay.Close()
			continue
		}

		s.mu.Lock()
		s.relays = append(s.relays, relay)
		s.mu.Unlock()

		connected++

		log.Printf("[NIP46] Listening on relay: %s", relayURL)

		go func(r *nostr.Relay, events <-chan *nostr.Event) {
			for {
				select {
				case <-s.ctx.Done():
					return

				case event, ok := <-events:
					if !ok {
						return
					}

					if event == nil {
						continue
					}

					log.Printf(
						"[NIP46] Request received: kind=%d pubkey=%s",
						event.Kind,
						event.PubKey[:12],
					)

					if err := s.HandleEvent(s.ctx, r, event); err != nil {
						log.Printf("[NIP46] Request processing failed: %v", err)
					}
				}
			}
		}(relay, sub.Events)
	}

	if connected == 0 {
		return errors.New("could not establish any NIP-46 relay subscription")
	}

	log.Printf("[NIP46] Signer started successfully: %d relay(s)", connected)

	return nil
}

// HandleEvent procesa un evento kind 24133.
func (s *Signer) HandleEvent(
	ctx context.Context,
	relay *nostr.Relay,
	event *nostr.Event,
) error {
	if event == nil || event.Kind != NIP46Kind {
		return ErrInvalidEvent
	}

	valid, err := event.CheckSignature()
	if err != nil || !valid {
		return ErrInvalidEvent
	}

	// Descartar duplicados (varios relays, replay básico).
	if s.alreadySeen(event.ID) {
		return nil
	}

	clientPubKey := event.PubKey

	// El evento debe estar dirigido al Remote Signer.
	signerPubKey, err := s.vault.PublicKey()
	if err != nil {
		return err
	}

	if !hasPTag(event.Tags, signerPubKey) {
		return ErrInvalidEvent
	}

	// Descifrar detectando el esquema (NIP-04 o NIP-44).
	plaintext, sch, err := s.decrypt(clientPubKey, event.Content)
	if err != nil {
		log.Printf("[NIP46] Decryption failed (scheme=%d): %v", sch, err)
		return ErrInvalidEvent
	}

	var reqData Request

	if err := json.Unmarshal([]byte(plaintext), &reqData); err != nil {
		log.Printf("[NIP46] Failed to parse request JSON: %v", err)
		return ErrInvalidEvent
	}

	if reqData.ID == "" || len(reqData.ID) > 128 {
		return ErrInvalidEvent
	}

	log.Printf(
		"[NIP46] RPC received: method=%s id=%s client=%s scheme=%d",
		reqData.Method,
		reqData.ID,
		clientPubKey[:12],
		sch,
	)

	resp := s.HandleRequest(ctx, clientPubKey, reqData)

	if resp.Error != "" {
		log.Printf("[NIP46] RPC error: method=%s error=%s", reqData.Method, resp.Error)
	} else {
		log.Printf("[NIP46] RPC success: method=%s", reqData.Method)
	}

	// Responder con el mismo esquema que usó el cliente.
	return s.publishResponse(ctx, relay, clientPubKey, resp, sch)
}

func hasPTag(tags nostr.Tags, pubkey string) bool {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "p" && tag[1] == pubkey {
			return true
		}
	}

	return false
}

// HandleRequest procesa los comandos NIP-46.
func (s *Signer) HandleRequest(
	ctx context.Context,
	clientPubKey string,
	req Request,
) Response {
	resp := Response{ID: req.ID}

	switch req.Method {
	case "connect":
		result, err := s.connect(clientPubKey, req.Params)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = result
		}

	case "ping":
		if !s.authorized(clientPubKey) {
			resp.Error = ErrUnauthorized.Error()
			break
		}

		resp.Result = "pong"

	case "get_public_key":
		if !s.authorized(clientPubKey) {
			resp.Error = ErrUnauthorized.Error()
			break
		}

		pubkey, err := s.vault.PublicKey()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = pubkey
		}

	case "sign_event":
		if !s.authorized(clientPubKey) {
			resp.Error = ErrUnauthorized.Error()
			break
		}

		result, err := s.signEvent(clientPubKey, req.Params)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = result
		}

	case "switch_relays":
		if !s.authorized(clientPubKey) {
			resp.Error = ErrUnauthorized.Error()
			break
		}
		// Simplemente respondemos ack o éxito para que el cliente no tire excepción
		resp.Result = "ack"

	case "logout":
		s.logout(clientPubKey)
		resp.Result = "ack"

	default:
		resp.Error = "unsupported NIP-46 method"
	}

	return resp
}

func (s *Signer) connect(
	clientPubKey string,
	params []string,
) (string, error) {
	if len(params) < 2 {
		return "", ErrPairing
	}

	remotePubKey := params[0]
	secret := params[1]

	ownPubKey, err := s.vault.PublicKey()
	if err != nil {
		return "", err
	}

	// Diagnóstico temporal: qué manda el cliente en params[0] (solo prefijo, sin secretos).
	if remotePubKey != ownPubKey {
		log.Printf("[NIP46] connect: params[0] differs from signer pubkey (len=%d, prefix=%.12s, nparams=%d)",
			len(remotePubKey), remotePubKey, len(params))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// El secreto de emparejamiento autentica la conexión (comparación en tiempo constante).
	if s.pairingSecret == "" ||
		time.Now().After(s.pairingExpiry) ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(s.pairingSecret)) != 1 {
		return "", ErrPairing
	}

	// El pairing secret solo puede usarse una vez.
	s.pairingSecret = ""
	s.pairingExpiry = time.Time{}

	permissions := map[string]bool{
		"ping":             true,
		"get_public_key":   true,
		"sign_event:22242": true,
		"sign_event:27235": true,
		"switch_relays":    true,
		"logout":           true,
	}

	if len(params) >= 3 {
		requested := strings.Split(params[2], ",")

		for _, permission := range requested {
			if permission == "" {
				continue
			}

			if strings.HasPrefix(permission, "sign_event") ||
				permission == "ping" ||
				permission == "get_public_key" ||
				permission == "logout" {
				permissions[permission] = true
			}
		}
	}

	s.sessions[clientPubKey] = &Session{
		ClientPubKey: clientPubKey,
		Permissions:  permissions,
		CreatedAt:    time.Now(),
	}

	return "ack", nil
}

func (s *Signer) authorized(clientPubKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[clientPubKey]

	return ok && time.Since(session.CreatedAt) < 24*time.Hour
}

func (s *Signer) signEvent(
	clientPubKey string,
	params []string,
) (string, error) {
	if len(params) < 1 || len(params[0]) > 16*1024 {
		return "", ErrInvalidEvent
	}

	s.mu.RLock()
	session := s.sessions[clientPubKey]
	s.mu.RUnlock()

	if session == nil {
		return "", ErrPermission
	}

	var event nostr.Event

	if err := json.Unmarshal([]byte(params[0]), &event); err != nil {
		return "", ErrInvalidEvent
	}

	log.Printf("[NIP46] sign_event requested: kind=%d", event.Kind)

	// Allowlist estricta de kinds.
	if !allowedKinds[event.Kind] {
		return "", ErrPermission
	}

	// Permiso general o específico del kind.
	if !session.Permissions["sign_event"] &&
		!session.Permissions[fmt.Sprintf("sign_event:%d", event.Kind)] {
		return "", ErrPermission
	}

	// Validación específica de autenticación HTTP.
	if event.Kind == HTTPAuthKind {
		if err := validateHTTPAuth(&event); err != nil {
			return "", err
		}
	}

	// Frescura del evento.
	now := time.Now()
	if event.CreatedAt == 0 {
		event.CreatedAt = nostr.Timestamp(now.Unix())
	} else {
		d := now.Sub(event.CreatedAt.Time())
		if d > maxEventSkew || d < -maxEventSkew {
			return "", ErrInvalidEvent
		}
	}

	pubkey, err := s.vault.PublicKey()
	if err != nil {
		return "", err
	}

	if event.PubKey != "" && event.PubKey != pubkey {
		return "", ErrUnauthorized
	}

	// El signer recalcula identidad, ID y firma.
	event.PubKey = pubkey
	event.ID = ""
	event.Sig = ""

	if err := s.vault.SignEvent(&event); err != nil {
		return "", err
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}

func (s *Signer) logout(clientPubKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, clientPubKey)
}

func (s *Signer) publishResponse(
	ctx context.Context,
	relay *nostr.Relay,
	clientPubKey string,
	resp Response,
	sch cipherScheme,
) error {
	plaintext, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	encrypted, err := s.encrypt(clientPubKey, string(plaintext), sch)
	if err != nil {
		return err
	}

	signerPubKey, err := s.vault.PublicKey()
	if err != nil {
		return err
	}

	event := nostr.Event{
		Kind:      NIP46Kind,
		CreatedAt: nostr.Now(),
		Content:   encrypted,
		Tags: nostr.Tags{
			nostr.Tag{"p", clientPubKey},
		},
		PubKey: signerPubKey,
	}

	if err := s.vault.SignEvent(&event); err != nil {
		return err
	}

	return relay.Publish(ctx, event)
}

// Close detiene las conexiones WebSocket.
func (s *Signer) Close() {
	s.cancel()

	for _, relay := range s.relays {
		_ = relay.Close()
	}
}

func (s *Signer) String() string {
	return fmt.Sprintf("NIP-46 signer (%d relays)", len(s.relays))
}
