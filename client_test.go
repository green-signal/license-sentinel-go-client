package licensesentinel

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientCheckAndVerifyUsesCachedCertificate(t *testing.T) {
	privateKey, _, certDER := mustCreateSelfSignedRSACertificate(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if len(caPEM) == 0 {
		t.Fatal("failed to encode test CA certificate")
	}

	var certCalls atomic.Int32
	var checkCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/certificate":
			certCalls.Add(1)
			if got := r.URL.Query().Get("client_id"); got != "test-client" {
				t.Fatalf("unexpected client_id: %q", got)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"certificate": base64.StdEncoding.EncodeToString(certDER),
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/signature/check":
			checkCalls.Add(1)
			var req map[string]string
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request failed: %v", err)
			}
			if req["client_id"] != "test-client" {
				t.Fatalf("unexpected client_id: %q", req["client_id"])
			}
			challenge := "challenge-for:" + req["client_nonce"]
			signatureB64 := mustSignChallengeB64(t, privateKey, challenge)

			writeJSON(t, w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"ok":         true,
					"code":       "ok",
					"checked_at": time.Now().UTC().Format(time.RFC3339Nano),
					"challenge":  challenge,
					"signature":  signatureB64,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := New(Config{
		BaseURL:      srv.URL,
		ClientID:     "test-client",
		TrustedCAPEM: string(caPEM),
	})
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	ctx := context.Background()
	first, err := client.CheckAndVerify(ctx, "nonce-1")
	if err != nil {
		t.Fatalf("check and verify failed: %v", err)
	}
	if !first.OK {
		t.Fatalf("expected ok result, got %+v", first)
	}

	second, err := client.CheckAndVerify(ctx, "nonce-2")
	if err != nil {
		t.Fatalf("second check and verify failed: %v", err)
	}
	if !second.OK {
		t.Fatalf("expected second result ok, got %+v", second)
	}

	if got := certCalls.Load(); got != 1 {
		t.Fatalf("expected certificate endpoint called once, got %d", got)
	}
	if got := checkCalls.Load(); got != 2 {
		t.Fatalf("expected check endpoint called twice, got %d", got)
	}
}

func TestClientCheckReturnsBusinessFailureWithoutError(t *testing.T) {
	_, _, certDER := mustCreateSelfSignedRSACertificate(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/signature/check" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, http.StatusServiceUnavailable, map[string]any{
			"result": map[string]any{
				"ok":         false,
				"code":       "sign_failed",
				"checked_at": time.Now().UTC().Format(time.RFC3339Nano),
			},
		})
	}))
	defer srv.Close()

	client, err := New(Config{
		BaseURL:      srv.URL,
		ClientID:     "test-client",
		TrustedCAPEM: string(caPEM),
	})
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	result, err := client.Check(context.Background(), "")
	if err != nil {
		t.Fatalf("expected business result without error, got %v", err)
	}
	if result.OK {
		t.Fatalf("expected non-ok result, got %+v", result)
	}
	if result.Code != ResultSignFailed {
		t.Fatalf("expected code %q, got %q", ResultSignFailed, result.Code)
	}
}

func TestRefreshCertificateInvalidBase64(t *testing.T) {
	_, _, certDER := mustCreateSelfSignedRSACertificate(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/certificate" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"result": map[string]any{
				"certificate": "%%%invalid-base64%%%",
			},
		})
	}))
	defer srv.Close()

	client, err := New(Config{
		BaseURL:      srv.URL,
		ClientID:     "test-client",
		TrustedCAPEM: string(caPEM),
	})
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	if _, err := client.RefreshCertificate(context.Background()); err == nil {
		t.Fatal("expected refresh certificate to fail for invalid base64")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode json failed: %v", err)
	}
}

func mustCreateSelfSignedRSACertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "license-sentinel-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate failed: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate failed: %v", err)
	}

	return privateKey, cert, certDER
}

func mustSignChallengeB64(t *testing.T, key *rsa.PrivateKey, challenge string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(challenge))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign challenge failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}
