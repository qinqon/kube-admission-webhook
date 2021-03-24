package chain

import (
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

type certificateChain struct {
	Options
	data               *CertificateChainData
	now                func() time.Time
	log                logr.Logger
}

func newChain(options *Options, data *CertificateChainData) (*certificateChain, error) {
	r := &certificateChain{
		Options:            *options,
		data:               data,
		now: triple.Now,
		log: logf.Log.WithName("certificate/chain"),
	}

	logger := r.log.WithName("newChain")

	err := r.Options.SetDefaultsAndValidate()
	if err != nil {
		return nil, err
	}

	// decode CA PEMs
	caKey, caCerts, err := keyPairPemToKeypair(data.CA.KeyPEM, data.CA.CertPEM)
	data.CA.keyPair = &triple.KeyPair{
		Key: caKey,
		Cert: getLastCert(caCerts),
	}
	if err != nil {
		// If CA key/cert is wrong or empty, rotate CA
		logger.Info("CA key pair invalid, will force full chain rotation", "err", err)
	}

	// decode Cert PEMs
	for _, certificateIssue := range data.CertificatesIssued {
		key, certs, err := keyPairPemToKeypair(certificateIssue.KeyPEM, certificateIssue.CertPEM)
		certificateIssue.key = key
		certificateIssue.certs = certs
		if err != nil {
			// If any service PEM is wrong or empty, rotate services
			// TODO[2]: consider filling empty service PEMs with new KeyPair
			logger.Info("Certificate key pair invalid, will force all issued certificates rotation",
				"name", certificateIssue.Name,
				"err", err,
			)
		}

		certificateIssue.caCerts = map[string][]*x509.Certificate{}
		for k, v := range certificateIssue.CACertPEM {
			certs, err := triple.ParseCertsPEM(v)
			certificateIssue.caCerts[k] = certs
			if err != nil {
				// If any CABundle is wrong or empty, rotate CA
				// TODO[1]: consider filling empty CA Bundles with the CA Cert PEM
				logger.Info("Certificate verification CA invalid, will force all issued certificates rotation",
					"name", certificateIssue.Name,
					"CA bundle", k,
					"err", err,
				)
			}
		}
	}

	return r, nil
}

func (c *certificateChain) getCARotateInterval() time.Duration {
	return c.CARotateInterval
}

func (c *certificateChain) getCAOverlapInterval() time.Duration {
	return c.CAOverlapInterval
}

func (c *certificateChain) getCertRotateInterval() time.Duration {
	return c.CertRotateInterval
}

func (c *certificateChain) getCertOverlapInterval() time.Duration {
	return c.CertOverlapInterval
}

// setCaKeypair sets a new CA KeyPair in all formats and adds it to all CA bundles
func (c *certificateChain) setCaKeyPair(keyPair *triple.KeyPair) error {
	c.data.CA.keyPair = keyPair
	c.data.CA.KeyPEM, c.data.CA.CertPEM = keyPairToKeyPairPem(keyPair)
	for _, certificateIssued := range c.data.CertificatesIssued {
		for k, caCerts := range certificateIssued.caCerts {
			caCerts = append(caCerts, keyPair.Cert)
			certificateIssued.caCerts[k] = caCerts
			certificateIssued.CACertPEM[k] = triple.EncodeCertsPEM(caCerts)
		}
	}
	return nil
}

// setCaCerts sets a CA certificate for a certificate issue in all formats
func (c *certificateChain) setCaCerts(certificateIssued *CertificateIssue, name string, caCerts []*x509.Certificate) {
	certificateIssued.caCerts[name] = caCerts
	certificateIssued.CACertPEM[name] = triple.EncodeCertsPEM(caCerts)
}

// setKeyResetCert sets a key pair for a certificate issue in all formats, existing certificates are removed
func (c *certificateChain) setKeyResetCert(certificateIssued *CertificateIssue, keyPair *triple.KeyPair) {
	certificateIssued.key = keyPair.Key
	certificateIssued.certs = []*x509.Certificate{keyPair.Cert}
	certificateIssued.KeyPEM, certificateIssued.CertPEM = keyPairToKeyPairPem(keyPair)
}

// setKeyAppendCert sets a key pair for a certificate issue in all formats, appended to previous certificates
func (c *certificateChain) setKeyAppendCert(certificateIssued *CertificateIssue, keyPair *triple.KeyPair) {
	certificateIssued.key = keyPair.Key
	certificateIssued.certs = append(certificateIssued.certs, keyPair.Cert)
	certificateIssued.KeyPEM = triple.EncodePrivateKeyPEM(keyPair.Key)
	certificateIssued.CertPEM = triple.EncodeCertsPEM(certificateIssued.certs)
}

// setCerts sets certificates for a certificate issue in all formats, preserving the previous key
func (c *certificateChain) setCerts(certificateIssued *CertificateIssue, certs []*x509.Certificate) {
	certificateIssued.certs = certs
	certificateIssued.CertPEM = triple.EncodeCertsPEM(certs)
}

// keyPairPemToKeypair converts KeyPair from PEM format
func keyPairPemToKeypair(keypem []byte, certpem []byte) (*rsa.PrivateKey, []*x509.Certificate, error) {
	key, err := triple.ParsePrivateKeyPEM(keypem)
	if err != nil {
		return nil, nil, err
	}
	rsakey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("Expected RSA key but found different type")
	}

	certs, err := triple.ParseCertsPEM(certpem)
	if err != nil {
		return nil, nil, err
	}

	return rsakey, certs, nil
}

// keyPairToKeyPairPem converts KeyPair to PEM format
func keyPairToKeyPairPem(keyPair *triple.KeyPair) (key []byte, cert []byte) {
	key = triple.EncodePrivateKeyPEM(keyPair.Key)
	cert = triple.EncodeCertPEM(keyPair.Cert)
	return
}

func (r *certificateChain) update() (time.Time, error) {
	logger := r.log.WithName("update")
	logger.Info("Checking certificate chain for rotation or cleanup")

	deadlineToRotateCA := r.findRotationDeadlineForCA()
	deadlineToRotateCerts := r.findRotationDeadlineForCerts()
	rotateCA := !r.now().Before(deadlineToRotateCA)
	rotateCerts := !r.now().Before(deadlineToRotateCerts)

	// Ensure certificate chain
	if !rotateCA {
		err := r.verifyTLS()
		if err != nil {
			logger.Info("Certificate chain failed verification, will force full chain rotation", "err", err)
			// Force rotation
			rotateCA = true
		}
	}

	// We have pass expiration time for the CA
	if rotateCA {
		// If rotate fails runtime-controller manager will re-enqueue it, so
		// it will be retried
		err := r.rotateAll()
		if err != nil {
			return time.Time{}, errors.Wrap(err, "Failed rotating certificate chain")
		}

		// Re-calculate deadlines
		deadlineToRotateCA = r.findRotationDeadlineForCA()
		deadlineToRotateCerts = r.findRotationDeadlineForCerts()
	} else if rotateCerts {
		// CA is ok but expiration but we have passed expiration time for chain certificates
		err := r.rotateCertsWithOverlap()
		if err != nil {
			return time.Time{}, errors.Wrap(err, "Failed rotating bundles")
		}

		// Re-calculate deadline
		deadlineToRotateCerts = r.findRotationDeadlineForCerts()
	}

	deadlineToCleanUpCACerts := r.findCleanUpDeadlineForCACerts()
	cleanUpCA := !r.now().Before(deadlineToCleanUpCACerts)

	// We have pass cleanup deadline let's do the cleanup
	if cleanUpCA {
		r.cleanUpCACerts()

		// Re-calculate deadline
		deadlineToCleanUpCACerts = r.findCleanUpDeadlineForCACerts()
	}

	deadlineToCleanUpCerts := r.findCleanUpDeadlineForCerts()
	cleanUpCerts := !r.now().Before(deadlineToCleanUpCerts)

	// We have pass cleanup deadline let's do the cleanup
	if cleanUpCerts {
		r.cleanUpCerts()

		// Re-calculate deadline
		deadlineToCleanUpCerts = r.findCleanUpDeadlineForCerts()
	}

	// Return the event that is going to happen sooner: all certificates rotation,
	// chains certificate rotation or ca bundle cleanup
	logger.Info("Calculating earliest chain deadline",
		"deadlineToRotateCA", deadlineToRotateCA,
		"deadlineToRotateCerts", deadlineToRotateCerts,
		"deadlineToCleanUpCACerts", deadlineToCleanUpCACerts,
		"deadlineToCleanUpCerts", deadlineToCleanUpCerts)
	updateAt := minTime(deadlineToRotateCA, deadlineToRotateCerts, deadlineToCleanUpCACerts, deadlineToCleanUpCerts)

	logger.Info("Certificate chain updated & current until next update", "updateAt", updateAt)
	return updateAt, nil
}

func (c *certificateChain) verifyTLS() error {
	for _, certificateIssued := range c.data.CertificatesIssued {
		for name, caCertPEM := range certificateIssued.CACertPEM {
			caCert := getLastCert(certificateIssued.caCerts[name])
			if !reflect.DeepEqual(caCert, c.data.CA.keyPair.Cert) {
				return errors.New("CA last certificate for verification and CA certificate are different")
			}

			err := triple.VerifyTLS(certificateIssued.CertPEM, certificateIssued.KeyPEM, caCertPEM)
			if err != nil {
				return errors.Wrapf(err, "Failed to verify certificate %s with named CA %s", certificateIssued.Name, name)
			}
		}
	}

	return nil
}

func getLastCert(certs []*x509.Certificate) *x509.Certificate {
	if len(certs) <= 0 {
		return nil
	}
	return certs[len(certs)-1]
}
