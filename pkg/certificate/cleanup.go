package certificate

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

func (m *Manager) earliestElapsedForCACertsCleanup() (time.Duration, error) {
	cas, err := m.getCACertsFromCABundle()
	if err != nil {
		return time.Duration(0), errors.Wrap(err, "failed getting CA certificates from CA bundle")
	}
	return m.earliestElapsedForCleanup(cas, m.caOverlapDuration)
}

// earliestElapsedForCleanup return a subtraction between earliestCleanupDeadline and
// `now`
func (m *Manager) earliestElapsedForCleanup(certificates []*x509.Certificate, overlapDuration time.Duration) (time.Duration, error) {
	deadline := m.earliestCleanupDeadlineForCerts(certificates, overlapDuration)
	now := m.now()
	elapsedForCleanup := deadline.Sub(now)
	m.log.Info(fmt.Sprintf("earliestElapsedForCleanup {now: %s, deadline: %s, elapsedForCleanup: %s}", now, deadline, elapsedForCleanup))
	return elapsedForCleanup, nil
}

// earliestCleanupDeadlineForCACerts will inspect CA certificates
// select the deadline based on certificate NotBefore + overlapDuration
// returning the daedline that is going to happend sooner
func (m *Manager) earliestCleanupDeadlineForCerts(certificates []*x509.Certificate, overlapDuration time.Duration) time.Time {
	var selectedCertificate *x509.Certificate

	// There is no overlap just return expiration time
	if len(certificates) == 1 {
		return certificates[0].NotAfter
	}

	for _, certificate := range certificates {
		if selectedCertificate == nil || certificate.NotBefore.Before(selectedCertificate.NotBefore) {
			selectedCertificate = certificate
		}
	}
	if selectedCertificate == nil {
		return m.now()
	}

	// Add the overlap duration since is the time certs are going to be living
	// add CABundle
	return selectedCertificate.NotBefore.Add(overlapDuration)
}

func (m *Manager) cleanUpCABundle() error {
	_, err := m.updateWebhookCABundleWithFunc(func([]byte) ([]byte, error) {
		cas, err := m.getCACertsFromCABundle()
		if err != nil {
			return nil, errors.Wrap(err, "failed getting ca certs to start cleanup")
		}
		cleanedCAs := m.cleanUpCertificates(cas, m.caOverlapDuration)
		pem := triple.EncodeCertsPEM(cleanedCAs)
		return pem, nil
	})

	if err != nil {
		return errors.Wrap(err, "failed updating webhook config after ca certificates cleanup")
	}
	return nil
}

func (m *Manager) cleanUpCertificates(certificates []*x509.Certificate, overlapDuration time.Duration) []*x509.Certificate {
	logger := m.log.WithName("cleanUpCertificates")
	logger.Info("Cleaning up expired or beyond overlap duration limit at CA bundle")
	// There is no overlap
	if len(certificates) <= 1 {
		return certificates
	}

	now := m.now()
	// create a zero-length slice with the same underlying array
	cleanedUpCertificates := certificates[:0]
	for i, certificate := range certificates {
		logger.Info("Checking certificate for cleanup", "now", now, "overlapDuration", overlapDuration, "NotBefore", certificate.NotBefore, "NotAfter", certificate.NotAfter)

		// Expired certificate are cleaned up
		caExpirationDate := certificate.NotAfter
		if now.After(caExpirationDate) {
			logger.Info("Cleaning up expired certificate", "now", now, "NotBefore", certificate.NotBefore, "NotAfter", certificate.NotAfter)
			continue
		}

		// Clean up certificates that pass CA Overlap Duration limit,
		// except for the last appended one (i.e. the last generated from a rotation) since we need at least one valid certificate
		caOverlapDate := certificate.NotBefore.Add(overlapDuration)
		if i != len(certificates)-1 && !now.Before(caOverlapDate) {
			logger.Info("Cleaning up certificate beyond CA overlap duration", "now", now, "overlapDuration", overlapDuration, "NotBefore", certificate.NotBefore, "NotAfter", certificate.NotAfter)
			continue
		}
		cleanedUpCertificates = append(cleanedUpCertificates, certificate)
	}
	return cleanedUpCertificates
}
