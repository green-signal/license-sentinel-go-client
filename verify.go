package licensesentinel

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

type VerifyOptions struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	DNSName       string
	CurrentTime   time.Time
	KeyUsages     []x509.ExtKeyUsage
}

// VerifyChallengeSignature verifies the RSA-SHA256 PKCS1v15 signature in signatureB64
// over the challenge string using the public key from cert.
// Only RSA certificates are currently supported.
func VerifyChallengeSignature(challenge string, signatureB64 string, cert *x509.Certificate) error {
	if cert == nil {
		return ErrCertificateNotLoaded
	}

	signatureRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("decode signature base64: %w", err)
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("certificate public key is not RSA")
	}

	sum := sha256.Sum256([]byte(challenge))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signatureRaw); err != nil {
		return fmt.Errorf("verify signature failed: %w", err)
	}

	return nil
}

func VerifyCertificate(cert *x509.Certificate, opts VerifyOptions) error {
	if cert == nil {
		return ErrCertificateNotLoaded
	}

	verifyOptions := x509.VerifyOptions{
		DNSName:       opts.DNSName,
		Intermediates: opts.Intermediates,
		Roots:         opts.Roots,
		CurrentTime:   opts.CurrentTime,
	}
	if len(opts.KeyUsages) > 0 {
		verifyOptions.KeyUsages = opts.KeyUsages
	} else {
		verifyOptions.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	if _, err := cert.Verify(verifyOptions); err != nil {
		return fmt.Errorf("verify certificate failed: %w", err)
	}

	return nil
}
