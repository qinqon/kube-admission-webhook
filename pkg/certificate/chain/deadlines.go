package chain

import (
	"crypto/x509"
	"time"
)

// nextRotationDeadlineForCA finds the earliest time a CA certificate needs to
// be rotated.
func (c *certificateChain) findRotationDeadlineForCA() time.Time {
	logger := c.log.WithName("findRotationDeadlineForCA")
	deadlines := make([]time.Time, 0)
	for _, certificateIssued := range c.data.CertificatesIssued {
		for _, certs := range certificateIssued.caCerts {
			cert := getLastCert(certs)
			if cert == nil {
				logger.Info("Found empty CA certificate, using an inmediate deadline")
				return time.Time{}
			}
			overlap := c.getCAOverlapInterval()
			deadline := nextRotationDeadlineForCert(cert, overlap)
			logger.Info("Considering CA certificate deadline", "notBefore", cert.NotBefore, "notAfter", cert.NotAfter, "overlap", overlap, "deadline", deadline)
			deadlines = append(deadlines, deadline)
		}
	}

	nextRotateDeadlineForCA := minTime(deadlines...)
	logger.Info("", "deadlines", deadlines, "nextRotateDeadlineForCA", nextRotateDeadlineForCA)
	return nextRotateDeadlineForCA
}

// findRotationDeadlineForCerts find the earliest time a certificate needs to be rotated
func (c *certificateChain) findRotationDeadlineForCerts() time.Time {
	logger := c.log.WithName("findRotationDeadlineForCerts")
	deadlines := make([]time.Time, 0, len(c.data.CertificatesIssued))
	for _, certificateIssued := range c.data.CertificatesIssued {
		cert := getLastCert(certificateIssued.certs)
		if cert == nil {
			logger.Info("Found empty certificate, using an inmediate deadline")
			return time.Time{}
		}
		overlap := c.getCertOverlapInterval()
		deadline := nextRotationDeadlineForCert(cert, overlap)
		logger.Info("Considering certificate deadline", "notBefore", cert.NotBefore, "notAfter", cert.NotAfter, "overlap", overlap, "deadline", deadline)
		deadlines = append(deadlines, deadline)
	}

	nextRotateDeadlineForCerts := minTime(deadlines...)
	logger.Info("", "deadlines", deadlines, "nextRotateDeadlineForCerts", nextRotateDeadlineForCerts)
	return nextRotateDeadlineForCerts
}

// nextRotationDeadlineForCert returns a value for the threshold at which the
// current certificate should be rotated, the expiration of the
// certificate - overlap
func nextRotationDeadlineForCert(certificate *x509.Certificate, overlap time.Duration) time.Time {
	notAfter := certificate.NotAfter
	totalDuration := float64(notAfter.Sub(certificate.NotBefore))
	deadlineDuration := totalDuration - float64(overlap)
	deadline := certificate.NotBefore.Add(time.Duration(deadlineDuration))
	return deadline
}

// findCleanUpDeadlineForCACerts finds the earliest time a CA certificate will
// expire and thus needs to be cleaned up.
func (c *certificateChain) findCleanUpDeadlineForCACerts() time.Time {
	c.log.WithName("findCleanUpDeadlineForCACerts").Info("Calculating cleanup deadline for CA certificates")
	certs := make([]*x509.Certificate, 0)
	for _, certificateIssued := range c.data.CertificatesIssued {
		for _, caCerts := range certificateIssued.caCerts {
			certs = append(certs, caCerts...)
		}
	}
	return c.findCleanUpDeadlineForCertList(certs)
}

// findCleanUpDeadlineForCerts finds the earliest time a certificate will
// expire and thus needs to be cleaned up.
func (c *certificateChain) findCleanUpDeadlineForCerts() time.Time {
	c.log.WithName("findCleanUpDeadlineForCerts").Info("Calculating cleanup deadline for certificates")
	certs := make([]*x509.Certificate, 0)
	for _, certificateIssued := range c.data.CertificatesIssued {
		for _, issuedCerts := range certificateIssued.certs {
			certs = append(certs, issuedCerts)
		}
	}
	return c.findCleanUpDeadlineForCertList(certs)
}

func (c *certificateChain) findCleanUpDeadlineForCertList(certificates []*x509.Certificate) time.Time {
	logger := c.log.WithName("findCleanUpDeadlineForCertList")
	var deadlines []time.Time
	for _, cert := range certificates {
		logger.Info("Considering cert deadline", "deadline", cert.NotAfter)
		deadlines = append(deadlines, cert.NotAfter)
	}
	deadline := minTime(deadlines...)
	logger.Info("", "deadline", deadline)
	return deadline
}

func minTime(values ...time.Time) time.Time {
	t := time.Time{}
	for i, e := range values {
		if i == 0 || e.Before(t) {
			t = e
		}
	}
	return t
}

func minDuration(values ...time.Duration) time.Duration {
	m := time.Duration(0)
	for i, e := range values {
		if i == 0 || e < m {
			m = e
		}
	}
	return m
}
