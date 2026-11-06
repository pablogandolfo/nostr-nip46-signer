package keyvault

import (
	"errors"
	"sync"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip44"
)

var (
	ErrVaultClosed = errors.New("vault is closed")
	ErrInvalidKey  = errors.New("invalid private key")
)

// Vault almacena la clave privada únicamente en RAM.
type Vault struct {
	mu     sync.RWMutex
	secret []byte
	pubkey string
	closed bool
}

// NIP04SharedSecret calcula el secreto ECDH sin exponer la clave privada.
func (v *Vault) NIP04SharedSecret(remotePubKey string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return nil, ErrVaultClosed
	}

	return nip04.ComputeSharedSecret(remotePubKey, string(v.secret))
}

// New crea un vault con una clave privada hex o nsec.
func New(privateKey string) (*Vault, error) {
	var secret string

	if len(privateKey) == 64 {
		secret = privateKey
	} else {
		prefix, decoded, err := nip19.Decode(privateKey)
		if err != nil || prefix != "nsec" {
			return nil, ErrInvalidKey
		}

		var ok bool
		secret, ok = decoded.(string)
		if !ok || len(secret) != 64 {
			return nil, ErrInvalidKey
		}
	}

	pubkey, err := nostr.GetPublicKey(secret)
	if err != nil {
		return nil, ErrInvalidKey
	}

	return &Vault{
		secret: []byte(secret),
		pubkey: pubkey,
	}, nil
}

// Generate crea una nueva identidad Nostr.
func Generate() (*Vault, error) {
	secret := nostr.GeneratePrivateKey()
	return New(secret)
}

// PublicKey devuelve la clave pública hex.
func (v *Vault) PublicKey() (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return "", ErrVaultClosed
	}

	return v.pubkey, nil
}

// SignEvent firma un evento sin exponer la clave privada.
func (v *Vault) SignEvent(event *nostr.Event) error {
	if event == nil {
		return errors.New("nil event")
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return ErrVaultClosed
	}

	// La clave privada solo se utiliza dentro del vault.
	return event.Sign(string(v.secret))
}

// Close invalida el vault y sobrescribe el buffer.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return
	}

	for i := range v.secret {
		v.secret[i] = 0
	}

	v.secret = nil
	v.pubkey = ""
	v.closed = true
}

// NIP44ConversationKey calcula la clave de conversación
// sin exponer la clave privada fuera del vault.
func (v *Vault) NIP44ConversationKey(
	remotePubKey string,
) ([32]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return [32]byte{}, ErrVaultClosed
	}

	return nip44.GenerateConversationKey(
		remotePubKey,
		string(v.secret),
	)
}

// Evita devolver un resultado ambiguo en futuras ampliaciones.
var _ = errors.New
