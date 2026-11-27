package keychain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// ServiceName is the default OS keychain service identifier.
	ServiceName = "inoreader-mcp"
	// DefaultAccount is the default OS keychain account identifier for OAuth tokens.
	DefaultAccount = "oauth-tokens"
	// ClientCredentialsAccount stores OAuth2 client_id + client_secret in the keychain.
	ClientCredentialsAccount = "client-credentials"

	keychainTimeout = 10 * time.Second
)

// ErrNotFound is returned when no credential exists in the keychain for the given key.
var ErrNotFound = errors.New("credential not found in keychain")

// Store persists opaque secret payloads in secure storage.
type Store interface {
	Get(service, account string) ([]byte, error)
	Set(service, account string, secret []byte) error
	Delete(service, account string) error
}

// DefaultStore returns the platform-native OS keychain store.
func DefaultStore() Store {
	return newPlatformStore()
}

func validateKey(service, account string) error {
	if !isSafeIdentifier(service) {
		return fmt.Errorf("invalid keychain service identifier")
	}
	if !isSafeIdentifier(account) {
		return fmt.Errorf("invalid keychain account identifier")
	}
	return nil
}

func isSafeIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	// First character must be alphanumeric to prevent leading '-' (CLI flag injection)
	// or leading '.' (hidden files / path traversal).
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		isPunct := c == '-' || c == '_' || c == '.'
		if !isAlpha && !isDigit && !isPunct {
			return false
		}
	}
	return true
}

// encodeSecret uses base64.RawStdEncoding ([A-Za-z0-9+/]) so the encoded payload
// never starts with '-' (preventing flag misinterpretation) and contains no whitespace or quotes.
func encodeSecret(secret []byte) string {
	return base64.RawStdEncoding.EncodeToString(secret)
}

func decodeSecret(encoded string) ([]byte, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, ErrNotFound
	}
	data, err := base64.RawStdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("corrupt keychain payload: %w", err)
	}
	return data, nil
}

func sanitizeKeychainError(msg string) string {
	msg = strings.TrimSpace(msg)
	if idx := strings.IndexByte(msg, '\n'); idx >= 0 {
		msg = msg[:idx]
	}
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return msg
}

// MemoryStore is a concurrency-safe in-memory Store for testing.
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string][]byte),
	}
}

func (m *MemoryStore) Get(service, account string) ([]byte, error) {
	if err := validateKey(service, account); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.data[service+"\x00"+account]
	if !ok {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(val))
	copy(cp, val)
	return cp, nil
}

func (m *MemoryStore) Set(service, account string, secret []byte) error {
	if err := validateKey(service, account); err != nil {
		return err
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[service+"\x00"+account] = cp
	return nil
}

func (m *MemoryStore) Delete(service, account string) error {
	if err := validateKey(service, account); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, service+"\x00"+account)
	return nil
}
