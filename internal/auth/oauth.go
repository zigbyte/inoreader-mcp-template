package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/inoreader-mcp/inoreader-mcp/internal/keychain"
)

const (
	DefaultAuthURL     = "https://www.inoreader.com/oauth2/auth"
	DefaultTokenURL    = "https://www.inoreader.com/oauth2/token"
	DefaultRedirectURI = "https://127.0.0.1:8787/callback"
	DefaultScope       = "read write"
	pinnedOAuthHost    = "www.inoreader.com"

	refreshSkew      = 2 * time.Minute
	maxTokenRespSize = 64 * 1024 // 64 KiB
	loginTimeout     = 3 * time.Minute
)

// ErrNotAuthenticated indicates no OAuth tokens exist in the keychain.
var ErrNotAuthenticated = errors.New("not authenticated: run `inoreader-mcp login` first")

// Token represents an InoReader OAuth2 token set stored in the OS keychain.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (t *Token) clone() *Token {
	if t == nil {
		return nil
	}
	cp := *t
	return &cp
}

// IsExpired reports whether the access token is missing or within the proactive refresh window.
func (t *Token) IsExpired(now time.Time) bool {
	if t == nil || t.AccessToken == "" {
		return true
	}
	if t.ExpiresAt.IsZero() {
		return false
	}
	return !now.Add(refreshSkew).Before(t.ExpiresAt)
}

// Config configures the OAuth2 manager.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scope        string
	AuthURL      string
	TokenURL     string
	ServiceName  string
	AccountName  string
	Store        keychain.Store
	HTTPClient   *http.Client
	OpenBrowser  func(string) error
	Now          func() time.Time
}

// Manager handles OAuth2 browser login, keychain persistence, in-memory token caching,
// and concurrency-safe automatic token refresh.
type Manager struct {
	cfg    Config
	mu     sync.Mutex
	cached *Token
}

// NewManager creates an OAuth2 Manager with safe defaults.
func NewManager(cfg Config) (*Manager, error) {
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)
	cfg.RedirectURI = strings.TrimSpace(cfg.RedirectURI)
	cfg.Scope = strings.TrimSpace(cfg.Scope)

	if cfg.RedirectURI == "" {
		cfg.RedirectURI = DefaultRedirectURI
	}
	if err := validateLoopbackRedirectURI(cfg.RedirectURI); err != nil {
		return nil, err
	}
	if cfg.Scope == "" {
		cfg.Scope = DefaultScope
	}
	if cfg.AuthURL == "" {
		cfg.AuthURL = DefaultAuthURL
	}
	if err := validateOAuthEndpointURL(cfg.AuthURL); err != nil {
		return nil, fmt.Errorf("invalid auth URL: %w", err)
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = DefaultTokenURL
	}
	if err := validateOAuthEndpointURL(cfg.TokenURL); err != nil {
		return nil, fmt.Errorf("invalid token URL: %w", err)
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = keychain.ServiceName
	}
	if cfg.AccountName == "" {
		cfg.AccountName = keychain.DefaultAccount
	}
	if cfg.Store == nil {
		cfg.Store = keychain.DefaultStore()
	}
	cfg.HTTPClient = hardenHTTPClient(cfg.HTTPClient)
	if cfg.OpenBrowser == nil {
		cfg.OpenBrowser = openBrowser
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{cfg: cfg}, nil
}

func hardenHTTPClient(in *http.Client) *http.Client {
	if in == nil {
		return &http.Client{
			Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	cp := *in
	if cp.Timeout == 0 {
		cp.Timeout = 20 * time.Second
	}
	cp.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cp
}

func validateOAuthEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("malformed URL")
	}
	host := u.Hostname()
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("loopback endpoint must use http or https")
		}
		return nil
	}
	if u.Scheme != "https" || !strings.EqualFold(host, pinnedOAuthHost) {
		return fmt.Errorf("endpoint host %q must be https://%s", raw, pinnedOAuthHost)
	}
	return nil
}

func validateLoopbackRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid redirect URI: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("redirect URI must use http or https scheme on loopback")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" {
		return fmt.Errorf("redirect URI host %q must be 127.0.0.1 or localhost", host)
	}
	if u.Port() == "" {
		return errors.New("redirect URI must include an explicit port")
	}
	return nil
}

// HasClientCredentials reports whether ClientID and ClientSecret are configured.
func (m *Manager) HasClientCredentials() bool {
	return m.cfg.ClientID != "" && m.cfg.ClientSecret != ""
}

// LoadToken reads the stored token (using the in-memory cache when warm) without refreshing.
func (m *Manager) LoadToken() (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, err := m.loadTokenLocked()
	if err != nil {
		return nil, err
	}
	return tok.clone(), nil
}

func (m *Manager) loadTokenLocked() (*Token, error) {
	if m.cached != nil {
		return m.cached, nil
	}
	raw, err := m.cfg.Store.Get(m.cfg.ServiceName, m.cfg.AccountName)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, ErrNotAuthenticated
		}
		return nil, err
	}
	var tok Token
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("invalid token payload in keychain: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, ErrNotAuthenticated
	}
	m.cached = &tok
	return m.cached, nil
}

func (m *Manager) saveTokenLocked(tok *Token) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	if err := m.cfg.Store.Set(m.cfg.ServiceName, m.cfg.AccountName, data); err != nil {
		return fmt.Errorf("save token to keychain: %w", err)
	}
	m.cached = tok.clone()
	return nil
}

// Logout removes stored OAuth tokens from the OS keychain and clears the in-memory cache.
func (m *Manager) Logout() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cached = nil
	return m.cfg.Store.Delete(m.cfg.ServiceName, m.cfg.AccountName)
}

// --- Client credentials in keychain ---

// ClientCredentials is the JSON payload stored under the client-credentials account.
type ClientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// SaveClientCredentials stores OAuth2 client_id + client_secret in the OS keychain.
func (m *Manager) SaveClientCredentials(clientID, clientSecret string) error {
	if clientID == "" || clientSecret == "" {
		return errors.New("both client_id and client_secret must be non-empty")
	}
	payload, err := json.Marshal(ClientCredentials{ClientID: clientID, ClientSecret: clientSecret})
	if err != nil {
		return fmt.Errorf("marshal client credentials: %w", err)
	}
	return m.cfg.Store.Set(m.cfg.ServiceName, keychain.ClientCredentialsAccount, payload)
}

// LoadClientCredentials reads OAuth2 client_id + client_secret from the OS keychain.
// Returns empty strings if not found (not an error).
func (m *Manager) LoadClientCredentials() (clientID, clientSecret string) {
	raw, err := m.cfg.Store.Get(m.cfg.ServiceName, keychain.ClientCredentialsAccount)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return "", ""
		}
		// Best-effort: log to stderr but don't fail — env vars may still provide them.
		fmt.Fprintf(os.Stderr, "warning: could not read client credentials from keychain: %v\n", err)
		return "", ""
	}
	var creds ClientCredentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		fmt.Fprintf(os.Stderr, "warning: corrupt client credentials in keychain: %v\n", err)
		return "", ""
	}
	return creds.ClientID, creds.ClientSecret
}

// DeleteClientCredentials removes stored client credentials from the OS keychain.
func (m *Manager) DeleteClientCredentials() error {
	return m.cfg.Store.Delete(m.cfg.ServiceName, keychain.ClientCredentialsAccount)
}

// GetAccessToken returns a valid access token, automatically refreshing if expired.
func (m *Manager) GetAccessToken(ctx context.Context) (string, error) {
	tok, err := m.LoadToken()
	if err != nil {
		return "", err
	}
	if !tok.IsExpired(m.cfg.Now()) {
		return tok.AccessToken, nil
	}
	refreshed, err := m.RefreshToken(ctx, tok.AccessToken)
	if err != nil {
		return "", err
	}
	return refreshed.AccessToken, nil
}

// RefreshToken refreshes the stored OAuth token. If another goroutine already refreshed
// the token since failedAccessToken was observed, the newly stored token is returned
// without issuing a duplicate refresh request.
func (m *Manager) RefreshToken(ctx context.Context, failedAccessToken string) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.loadTokenLocked()
	if err != nil {
		return nil, err
	}
	// Double-check: another goroutine may have already refreshed while we waited on m.mu.
	if failedAccessToken != "" && current.AccessToken != failedAccessToken && !current.IsExpired(m.cfg.Now()) {
		return current.clone(), nil
	}
	if current.RefreshToken == "" {
		return nil, errors.New("oauth token expired and no refresh_token is available; run `inoreader-mcp login` again")
	}
	if !m.HasClientCredentials() {
		return nil, errors.New("cannot refresh token: INOREADER_CLIENT_ID and INOREADER_CLIENT_SECRET must be set")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {current.RefreshToken},
		"client_id":     {m.cfg.ClientID},
		"client_secret": {m.cfg.ClientSecret},
	}
	tok, err := m.requestToken(ctx, form)
	if err != nil {
		return nil, err
	}
	// Preserve existing refresh_token if InoReader omits it on refresh.
	if tok.RefreshToken == "" {
		tok.RefreshToken = current.RefreshToken
	}
	if tok.Scope == "" {
		tok.Scope = current.Scope
	}
	if err := m.saveTokenLocked(tok); err != nil {
		return nil, err
	}
	return tok.clone(), nil
}

// Login runs the browser-based OAuth2 authorization code flow using a local loopback callback server.
// Status messages are written to statusOut (typically os.Stderr) so stdout remains clean.
func (m *Manager) Login(ctx context.Context, statusOut io.Writer) (*Token, error) {
	if !m.HasClientCredentials() {
		return nil, errors.New("INOREADER_CLIENT_ID and INOREADER_CLIENT_SECRET must be set before login")
	}
	u, err := url.Parse(m.cfg.RedirectURI)
	if err != nil {
		return nil, err
	}
	callbackPath := u.Path
	if callbackPath == "" {
		callbackPath = "/callback"
	}

	state, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate oauth state: %w", err)
	}

	// Bind strictly to the validated loopback host (127.0.0.1 or localhost).
	listenHost := u.Hostname()
	listenAddr := net.JoinHostPort(listenHost, u.Port())
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
	defer ln.Close()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	boundPort := fmt.Sprintf("%d", tcpAddr.Port)

	actualRedirectURI := m.cfg.RedirectURI
	if u.Port() == "0" {
		uCopy := *u
		uCopy.Host = net.JoinHostPort(listenHost, boundPort)
		actualRedirectURI = uCopy.String()
	}

	type callbackResult struct {
		code string
		err  error
	}
	resCh := make(chan callbackResult, 1)
	var once sync.Once
	sendResult := func(r callbackResult) {
		once.Do(func() { resCh <- r })
	}

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, callbackErrorHTML)
			return
		}
		if !isExpectedLoopbackHost(r.Host, boundPort) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, callbackErrorHTML)
			return
		}

		q := r.URL.Query()
		gotState := q.Get("state")
		if len(gotState) != len(state) || subtle.ConstantTimeCompare([]byte(gotState), []byte(state)) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, callbackErrorHTML)
			if statusOut != nil {
				fmt.Fprintln(statusOut, "Warning: ignored OAuth callback with invalid or missing state parameter.")
			}
			return
		}
		if errCode := q.Get("error"); errCode != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, callbackErrorHTML)
			sendResult(callbackResult{err: fmt.Errorf("oauth authorization denied: %s", sanitizeShort(errCode))})
			return
		}
		code := q.Get("code")
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, callbackErrorHTML)
			sendResult(callbackResult{err: errors.New("oauth callback missing authorization code")})
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, callbackSuccessHTML)
		sendResult(callbackResult{code: code})
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	serveLn := ln
	if u.Scheme == "https" {
		tlsCert, err := generateSelfSignedLoopbackCert()
		if err != nil {
			return nil, fmt.Errorf("generate loopback TLS cert: %w", err)
		}
		serveLn = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		})
	}

	serveErrCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(serveLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- err
		}
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	authURL, err := m.buildAuthURL(actualRedirectURI, state)
	if err != nil {
		return nil, err
	}
	if statusOut != nil {
		fmt.Fprintf(statusOut, "Opening browser for InoReader OAuth2 login...\n")
		fmt.Fprintf(statusOut, "If the browser does not open automatically, visit:\n%s\n", authURL)
	}
	if err := m.cfg.OpenBrowser(authURL); err != nil && statusOut != nil {
		fmt.Fprintf(statusOut, "Warning: could not open browser automatically (%v). Please open the URL above manually.\n", err)
	}

	loginCtx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	var authCode string
	select {
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		authCode = res.code
	case err := <-serveErrCh:
		return nil, fmt.Errorf("callback server error: %w", err)
	case <-loginCtx.Done():
		return nil, fmt.Errorf("oauth login timed out or cancelled: %w", loginCtx.Err())
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {m.cfg.ClientID},
		"client_secret": {m.cfg.ClientSecret},
		"redirect_uri":  {actualRedirectURI},
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tok, err := m.requestToken(ctx, form)
	if err != nil {
		return nil, err
	}
	if err := m.saveTokenLocked(tok); err != nil {
		return nil, err
	}
	return tok.clone(), nil
}

func isExpectedLoopbackHost(hostHeader, port string) bool {
	h, p, err := net.SplitHostPort(hostHeader)
	if err != nil || p != port {
		return false
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func (m *Manager) buildAuthURL(redirectURI, state string) (string, error) {
	u, err := url.Parse(m.cfg.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth URL: %w", err)
	}
	q := u.Query()
	q.Set("client_id", m.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", m.cfg.Scope)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (m *Manager) requestToken(ctx context.Context, form url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := m.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenRespSize))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token endpoint returned HTTP %d with invalid JSON", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if tr.Error != "" {
			return nil, fmt.Errorf("oauth token error (%s): %s", sanitizeShort(tr.Error), sanitizeShort(tr.ErrorDesc))
		}
		return nil, fmt.Errorf("oauth token endpoint returned HTTP %d", resp.StatusCode)
	}
	if tr.AccessToken == "" {
		return nil, errors.New("oauth token response missing access_token")
	}

	tok := &Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scope:        tr.Scope,
	}
	if tok.TokenType == "" {
		tok.TokenType = "Bearer"
	}
	if tr.ExpiresIn > 0 {
		tok.ExpiresAt = m.cfg.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tok, nil
}

func randomHex(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func openBrowser(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("refusing to open non-http(s) URL")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("/usr/bin/open", rawURL)
	case "linux":
		bin := "xdg-open"
		if _, err := os.Stat("/usr/bin/xdg-open"); err == nil {
			bin = "/usr/bin/xdg-open"
		}
		cmd = exec.Command(bin, rawURL)
	case "windows":
		bin := "rundll32.exe"
		if root := os.Getenv("SystemRoot"); root != "" {
			candidate := filepath.Join(root, "System32", "rundll32.exe")
			if _, err := os.Stat(candidate); err == nil {
				bin = candidate
			}
		}
		cmd = exec.Command(bin, "url.dll,FileProtocolHandler", rawURL)
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap child process in background so it does not become a zombie.
	go func() { _ = cmd.Wait() }()
	return nil
}

func sanitizeShort(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

func generateSelfSignedLoopbackCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

const callbackSuccessHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>InoReader MCP — Authorization Received</title></head>
<body style="font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;">
<h1>Authorization Received</h1>
<p>InoReader authorization was received. Check your terminal to confirm token storage completed. You can close this window.</p>
</body>
</html>`

const callbackErrorHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>InoReader MCP — Authentication Failed</title></head>
<body style="font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;">
<h1>Authentication Failed</h1>
<p>InoReader authentication could not be completed. Check your terminal for details and try again.</p>
</body>
</html>`
