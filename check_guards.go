package licensesentinel

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	expectedServiceID = "license-sentinel"
	maxChallengeAge   = 5 * time.Minute
	maxFutureSkew     = 2 * time.Minute
	minRSASignatureSz = 128
)

type parsedChallenge struct {
	ServiceID   string
	Timestamp   time.Time
	Nonce       []byte
	ClientNonce string
}

func validateHTTPResult(statusCode int, result CheckResult) error {
	if result.OK && statusCode != http.StatusOK {
		return fmt.Errorf("invalid result envelope: ok result with HTTP %d", statusCode)
	}
	if !result.OK && statusCode == http.StatusOK {
		return errors.New("invalid result envelope: non-ok result with HTTP 200")
	}
	return nil
}

func validateBusinessResult(result CheckResult) error {
	if result.OK && result.Code != ResultOK {
		return fmt.Errorf("invalid successful result code: %q", result.Code)
	}
	if !result.OK && result.Code == ResultOK {
		return errors.New("invalid failed result code: ok")
	}
	if !result.OK {
		return nil
	}

	if strings.TrimSpace(result.Challenge) == "" {
		return errors.New("invalid successful result: challenge is empty")
	}
	if strings.TrimSpace(result.Signature) == "" {
		return errors.New("invalid successful result: signature is empty")
	}

	signatureRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(result.Signature))
	if err != nil {
		return fmt.Errorf("invalid signature base64: %w", err)
	}
	if len(signatureRaw) < minRSASignatureSz {
		return fmt.Errorf("invalid signature size: %d", len(signatureRaw))
	}

	return nil
}

func parseAndValidateChallenge(challengeRaw string, expectedClientNonce string) (parsedChallenge, error) {
	challenge := strings.TrimSpace(challengeRaw)
	if challenge == "" {
		return parsedChallenge{}, errors.New("challenge is empty")
	}

	parts := strings.Split(challenge, ";")
	if len(parts) < 3 || len(parts) > 4 {
		return parsedChallenge{}, errors.New("challenge has invalid number of fields")
	}

	expectOrder := []string{"service", "ts", "nonce", "client_nonce"}
	values := make(map[string]string, len(parts))

	for i, part := range parts {
		if strings.TrimSpace(part) == "" {
			return parsedChallenge{}, errors.New("challenge contains empty segment")
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return parsedChallenge{}, fmt.Errorf("challenge segment %q is malformed", part)
		}

		key := strings.TrimSpace(kv[0])
		if key == "" {
			return parsedChallenge{}, errors.New("challenge contains empty key")
		}
		if i >= len(expectOrder) || key != expectOrder[i] {
			return parsedChallenge{}, fmt.Errorf("challenge field %q is out of order", key)
		}
		if _, exists := values[key]; exists {
			return parsedChallenge{}, fmt.Errorf("duplicate challenge field: %s", key)
		}
		values[key] = kv[1]
	}

	serviceID := strings.TrimSpace(values["service"])
	if serviceID == "" {
		return parsedChallenge{}, errors.New("challenge service is empty")
	}
	if serviceID != expectedServiceID {
		return parsedChallenge{}, fmt.Errorf("unexpected challenge service: %q", serviceID)
	}

	tsRaw := strings.TrimSpace(values["ts"])
	if tsRaw == "" {
		return parsedChallenge{}, errors.New("challenge timestamp is empty")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, tsRaw)
	if err != nil {
		return parsedChallenge{}, fmt.Errorf("parse challenge timestamp: %w", err)
	}

	nonceRaw := strings.TrimSpace(values["nonce"])
	if nonceRaw == "" {
		return parsedChallenge{}, errors.New("challenge nonce is empty")
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceRaw)
	if err != nil {
		return parsedChallenge{}, fmt.Errorf("decode challenge nonce: %w", err)
	}
	if len(nonce) == 0 {
		return parsedChallenge{}, errors.New("challenge nonce is empty after decode")
	}

	clientNonce := ""
	if raw, ok := values["client_nonce"]; ok {
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			return parsedChallenge{}, fmt.Errorf("decode challenge client_nonce: %w", err)
		}
		clientNonce = decoded
	}

	expectedClientNonce = strings.TrimSpace(expectedClientNonce)
	if expectedClientNonce != "" && clientNonce != expectedClientNonce {
		return parsedChallenge{}, fmt.Errorf("client_nonce mismatch: expected %q, got %q", expectedClientNonce, clientNonce)
	}

	return parsedChallenge{
		ServiceID:   serviceID,
		Timestamp:   timestamp,
		Nonce:       nonce,
		ClientNonce: clientNonce,
	}, nil
}

func validateChallengeTimestamp(challengeTime time.Time, now time.Time) error {
	if challengeTime.IsZero() {
		return errors.New("challenge timestamp is zero")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	challengeTime = challengeTime.UTC()
	now = now.UTC()

	if challengeTime.After(now.Add(maxFutureSkew)) {
		return fmt.Errorf("challenge timestamp is too far in the future: %s", challengeTime.Format(time.RFC3339Nano))
	}
	if challengeTime.Before(now.Add(-maxChallengeAge)) {
		return fmt.Errorf("challenge timestamp is too old: %s", challengeTime.Format(time.RFC3339Nano))
	}
	return nil
}
