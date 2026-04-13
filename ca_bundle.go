package licensesentinel

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const trustedCAPEMSHA256 = "88e1bea647a29f453627b37b8e76c0981d2e49691a005d2b033780bdad7e4d82"

var (
	trustedCAPEMOnce sync.Once
	trustedCAPEM     string
	trustedCAPEMErr  error
)

var trustedCAXORKey = [...]byte{
	103, 115, 45, 99, 97, 45, 111, 98, 102, 45, 118, 49, 58, 58, 115, 112,
	108, 105, 116, 45, 120, 111, 114, 58, 58, 50, 48, 50, 54,
}

// trustedCACipherParts stores an obfuscated PEM payload.
// The value is reconstructed only in memory on demand.
var trustedCACipherParts = [...]string{
	"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",
	"RFkAVQ==",
}

func loadDefaultTrustedCAPEM() (string, error) {
	trustedCAPEMOnce.Do(func() {
		trustedCAPEM, trustedCAPEMErr = decodeTrustedCAPEM()
	})
	return trustedCAPEM, trustedCAPEMErr
}

func decodeTrustedCAPEM() (string, error) {
	cipherB64 := strings.Join(trustedCACipherParts[:], "")
	cipherRaw, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", fmt.Errorf("decode trusted CA payload: %w", err)
	}
	if len(cipherRaw) == 0 {
		return "", errors.New("trusted CA payload is empty")
	}

	plain := make([]byte, len(cipherRaw))
	keyLen := len(trustedCAXORKey)
	for i := range cipherRaw {
		plain[i] = cipherRaw[i] ^ trustedCAXORKey[(i+17)%keyLen]
	}

	sum := sha256.Sum256(plain)
	if fmt.Sprintf("%x", sum[:]) != trustedCAPEMSHA256 {
		return "", errors.New("trusted CA integrity check failed")
	}

	pemPayload := string(plain)
	if !strings.Contains(pemPayload, "-----BEGIN CERTIFICATE-----") ||
		!strings.Contains(pemPayload, "-----END CERTIFICATE-----") {
		return "", errors.New("trusted CA payload format is invalid")
	}

	return pemPayload, nil
}
