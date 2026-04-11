package licensesentinel

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultAPIPath = "/api/v1"

var ErrCertificateNotLoaded = errors.New("certificate is not loaded")
var ErrTrustedCAIsNotConfigured = errors.New("trusted CA is not configured")

type Config struct {
	BaseURL    string
	APIPath    string
	ClientID   string
	HTTPClient *http.Client
	// UnixSocketPath enables UDS transport for requests to license-sentinel.
	// When set, BaseURL may be omitted.
	UnixSocketPath string

	// TrustedCAPEM overrides the built-in CA certificate bundle.
	// Leave empty in production usage where CA is embedded in SDK.
	TrustedCAPEM string
}

type Client struct {
	httpClient *http.Client
	apiBaseURL string
	clientID   string

	mu      sync.RWMutex
	certDER []byte
	cert    *x509.Certificate
	roots   *x509.CertPool
}

type HTTPStatusError struct {
	StatusCode int
	Endpoint   string
	Message    string
}

func (e *HTTPStatusError) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		return fmt.Sprintf("license-sentinel request failed: %s returned HTTP %d", e.Endpoint, e.StatusCode)
	}
	return fmt.Sprintf("license-sentinel request failed: %s returned HTTP %d: %s", e.Endpoint, e.StatusCode, e.Message)
}

type checkRequest struct {
	ClientID    string `json:"client_id"`
	ClientNonce string `json:"client_nonce,omitempty"`
}

type certificateResponse struct {
	Certificate string `json:"certificate"`
}

type serverAnswer[T any] struct {
	Result  T      `json:"result"`
	Warning string `json:"warning,omitempty"`
}

type serverError struct {
	Error string `json:"error"`
}

func New(cfg Config) (*Client, error) {
	unixSocketPath := strings.TrimSpace(cfg.UnixSocketPath)
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if unixSocketPath == "" {
		if baseURL == "" {
			return nil, errors.New("base URL is required")
		}
	} else if baseURL == "" {
		baseURL = "http://unix"
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, errors.New("client ID is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		if unixSocketPath != "" {
			httpClient = newUDSHTTPClient(unixSocketPath, 5*time.Second)
		} else {
			httpClient = &http.Client{Timeout: 5 * time.Second}
		}
	}

	apiPath := normalizeAPIPath(cfg.APIPath)
	baseURL = strings.TrimRight(baseURL, "/")

	roots, err := parseTrustedRoots(cfg.TrustedCAPEM)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpClient: httpClient,
		apiBaseURL: baseURL + apiPath,
		clientID:   clientID,
		roots:      roots,
	}, nil
}

func newUDSHTTPClient(socketPath string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func (c *Client) ClientID() string {
	return c.clientID
}

func (c *Client) Init(ctx context.Context) error {
	_, err := c.RefreshCertificate(ctx)
	return err
}

func (c *Client) RefreshCertificate(ctx context.Context) (*x509.Certificate, error) {
	endpoint := c.apiBaseURL + "/certificate"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build certificate request: %w", err)
	}

	query := req.URL.Query()
	query.Set("client_id", c.clientID)
	req.URL.RawQuery = query.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request certificate: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, parseStatusError(resp, endpoint)
	}

	payload, err := decodeServerAnswer[certificateResponse](resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decode certificate response: %w", err)
	}

	certB64 := strings.TrimSpace(payload.Result.Certificate)
	if certB64 == "" {
		return nil, errors.New("certificate payload is empty")
	}

	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, fmt.Errorf("decode certificate base64: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	if err := VerifyCertificate(cert, VerifyOptions{
		Roots:     c.roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.certDER = append([]byte(nil), certDER...)
	c.cert = cert
	c.mu.Unlock()

	return cert, nil
}

func (c *Client) Check(ctx context.Context, clientNonce string) (CheckResult, error) {
	result, err := c.checkRaw(ctx, clientNonce)
	if err != nil {
		return CheckResult{}, err
	}
	if !result.OK {
		return result, nil
	}

	if err := c.validateCheckResult(ctx, result); err != nil {
		return CheckResult{}, err
	}

	return result, nil
}

func (c *Client) checkRaw(ctx context.Context, clientNonce string) (CheckResult, error) {
	endpoint := c.apiBaseURL + "/signature/check"

	requestBody := checkRequest{
		ClientID:    c.clientID,
		ClientNonce: strings.TrimSpace(clientNonce),
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return CheckResult{}, fmt.Errorf("marshal check request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return CheckResult{}, fmt.Errorf("build check request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CheckResult{}, fmt.Errorf("request check: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusServiceUnavailable:
		answer, err := decodeServerAnswer[CheckResult](resp.Body)
		if err != nil {
			return CheckResult{}, fmt.Errorf("decode check response: %w", err)
		}
		return answer.Result, nil
	default:
		return CheckResult{}, parseStatusError(resp, endpoint)
	}
}

func (c *Client) CheckAndVerify(ctx context.Context, clientNonce string) (CheckResult, error) {
	return c.Check(ctx, clientNonce)
}

func (c *Client) validateCheckResult(ctx context.Context, result CheckResult) error {
	cert, err := c.getOrRefreshCertificate(ctx)
	if err != nil {
		return err
	}

	if err := VerifyChallengeSignature(result.Challenge, result.Signature, cert); err != nil {
		return err
	}

	if err := VerifyCertificate(cert, VerifyOptions{
		Roots:     c.roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return err
	}

	return nil
}

func (c *Client) CertificateDER() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.certDER) == 0 {
		return nil
	}
	return append([]byte(nil), c.certDER...)
}

func (c *Client) Certificate() *x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert
}

func (c *Client) getOrRefreshCertificate(ctx context.Context) (*x509.Certificate, error) {
	c.mu.RLock()
	cached := c.cert
	c.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	return c.RefreshCertificate(ctx)
}

func normalizeAPIPath(apiPath string) string {
	p := strings.TrimSpace(apiPath)
	if p == "" {
		return defaultAPIPath
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func decodeServerAnswer[T any](r io.Reader) (serverAnswer[T], error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var answer serverAnswer[T]
	if err := dec.Decode(&answer); err != nil {
		return serverAnswer[T]{}, err
	}
	return answer, nil
}

func parseStatusError(resp *http.Response, endpoint string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	message := strings.TrimSpace(string(body))
	if len(body) != 0 {
		var payload serverError
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			message = strings.TrimSpace(payload.Error)
		}
	}

	return &HTTPStatusError{
		StatusCode: resp.StatusCode,
		Endpoint:   endpoint,
		Message:    message,
	}
}

func parseTrustedRoots(trustedCAPEM string) (*x509.CertPool, error) {
	pemPayload := strings.TrimSpace(trustedCAPEM)
	if pemPayload == "" {
		pemPayload = strings.TrimSpace(defaultTrustedCAPEM)
	}
	if pemPayload == "" {
		return nil, ErrTrustedCAIsNotConfigured
	}

	roots := x509.NewCertPool()
	certsAdded := 0
	remaining := []byte(pemPayload)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse trusted CA certificate: %w", err)
		}
		roots.AddCert(cert)
		certsAdded++
	}

	if certsAdded == 0 {
		return nil, ErrTrustedCAIsNotConfigured
	}

	return roots, nil
}
