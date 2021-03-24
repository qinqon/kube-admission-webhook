package chain

import (
	"crypto/x509"
)

func (c *certificateChain) cleanUpCertificateList(certificates []*x509.Certificate) []*x509.Certificate {
	logger := c.log.WithName("cleanUpCertificateList")

	// There is no overlap
	if len(certificates) <= 1 {
		return certificates
	}

	now := c.now()
	// create a zero-length slice with the same underlying array
	cleanedUpCertificates := certificates[:0]
	for _, certificate := range certificates {
		logger.Info("Considering certificate for cleanup", "now", now, "NotBefore", certificate.NotBefore, "NotAfter", certificate.NotAfter)

		// Expired certificate are cleaned up
		expirationDate := certificate.NotAfter
		if !expirationDate.After(now) {
			logger.Info("Cleaning up expired certificate")
			continue
		}

		cleanedUpCertificates = append(cleanedUpCertificates, certificate)
	}

	return cleanedUpCertificates
}

func (c *certificateChain) cleanUpCACerts() {
	c.log.WithName("cleanUpCACerts").Info("Cleaning up CA certificates")
	for _, certificateIssued := range c.data.CertificatesIssued {
		for k, caCerts := range certificateIssued.caCerts {
			caCerts = c.cleanUpCertificateList(caCerts)
			c.setCaCerts(certificateIssued, k, caCerts)
		}
	}
}

func (c *certificateChain) cleanUpCerts() {
	c.log.WithName("cleanUpCerts").Info("Cleaning up issued certificates")
	for _, certificateIssued := range c.data.CertificatesIssued {
		certs := c.cleanUpCertificateList(certificateIssued.certs)
		c.setCerts(certificateIssued, certs)
	}
}
