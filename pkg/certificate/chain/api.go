package chain

import (
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

// CertificateIssue contains details about an issued certificate, including the
// private key and named CA certificates known to verify the issued certificate.
type CertificateIssue struct {
	Name      string
	IPs       []string
	Hostnames []string
	KeyPEM    []byte
	CertPEM   []byte
	CACertPEM map[string][]byte

	// decoded data
	key     *rsa.PrivateKey
	certs   []*x509.Certificate
	caCerts map[string][]*x509.Certificate
}

// CA contains details about a certification authority
type CA struct {
	Name    string
	KeyPEM  []byte
	CertPEM []byte

	// decoded data
	keyPair *triple.KeyPair
}

// CertificateChainData represents details about a certification authority and
// named certificates issued by that authority.
type CertificateChainData struct {
	CertificatesIssued map[string]*CertificateIssue
	CA                 CA
}

// Options that allow to customize certificate rotation.
type Options struct {
	// CARotateInterval configurated duration for CA and certificate
	CARotateInterval time.Duration

	// CAOverlapInterval the duration of CA Certificates at CABundle if
	// not set it will default to CARotateInterval
	CAOverlapInterval time.Duration

	// CertRotateInterval configurated duration for of service certificate
	// the the webhook configuration is referencing different services all
	// of them will share the same duration
	CertRotateInterval time.Duration

	// CertOverlapInterval the duration of service certificates at bundle if
	// not set it will default to CertRotateInterval
	CertOverlapInterval time.Duration
}

// Update keeps the certificate chain data currrent by:
// - Rotating all issued certificates when at least one is expired or in the
//   rotation overlap window or missing.
// - Rotating the CA and all issued certificates when the CA certificate is
//   expired or in the rotation overlap window or missing.
// - Rotating the CA and all issued certificates when the certificate chain
//   cannot be succesfully verified.
// - Cleaning up all expired certificates
// Returns a Time prediction when Update should be called again for the above
// actions to be performed
func Update(options *Options, data *CertificateChainData) (time.Time, error) {
	chain, err := newChain(options, data)
	if err != nil {
		return time.Time{}, err
	}

	return chain.update()
}

// Verify the certificate chain. An error is returned if it does not.
func Verify(options *Options, data *CertificateChainData) error {
	chain, err := newChain(options, data)
	if err != nil {
		return err
	}

	return chain.verifyTLS()
}
