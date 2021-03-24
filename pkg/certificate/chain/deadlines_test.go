package chain

import (
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const maxNegativeDuration time.Duration = -1 << 63

var _ = Describe("Deadlines", func() {
	var (
		now time.Time
	)
	BeforeEach(func() {
		now = time.Now()
	})
	type certificateExpiration struct {
		notBefore time.Duration
		notAfter  time.Duration
	}
	expirationsToCertificates := func(expirations []certificateExpiration) []*x509.Certificate {
		certificates := []*x509.Certificate{}
		for _, expiration := range expirations {
			certificates = append(certificates, &x509.Certificate{
				NotBefore: now.Add(expiration.notBefore),
				NotAfter:  now.Add(expiration.notAfter),
			})
		}
		return certificates
	}

	type findDeadlineForCertsCleanupCase struct {
		certsExpiration []certificateExpiration
		expectedElapsed time.Duration
	}
	DescribeTable("findDeadlineForCertsCleanup",
		func(c findDeadlineForCertsCleanupCase) {

			r := certificateChain{
				now: func() time.Time { return now },
				log: log,
			}

			certificates := expirationsToCertificates(c.certsExpiration)

			obtainedDeadline := r.findCleanUpDeadlineForCertList(certificates)
			Expect(obtainedDeadline.Sub(now)).To(Equal(c.expectedElapsed))
		},
		Entry("empty certificates, deadline is minimum", findDeadlineForCertsCleanupCase{
			certsExpiration: []certificateExpiration{},
			expectedElapsed: maxNegativeDuration,
		}),
		Entry("one certificate, deadline is certificate's expiration time", findDeadlineForCertsCleanupCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  99 * time.Hour,
				},
			},
			expectedElapsed: 99 * time.Hour,
		}),
		Entry("first one sooner, deadline taken from it", findDeadlineForCertsCleanupCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -3 * time.Hour,
					notAfter:  88 * time.Hour,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
			expectedElapsed: 88 * time.Hour,
		}),
		Entry("second one sooner, deadline taken from it", findDeadlineForCertsCleanupCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -3 * time.Hour,
					notAfter:  88 * time.Hour,
				},
				{
					notBefore: -4 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
			expectedElapsed: 77 * time.Hour,
		}),
		Entry("third one sooner, deadline taken from it", findDeadlineForCertsCleanupCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: 0 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  66 * time.Hour,
				},
			},
			expectedElapsed: 66 * time.Hour,
		}),
	)

	type nextRotationDeadlineForCertCase struct {
		notBefore    time.Duration
		notAfter     time.Duration
		overlap      time.Duration
		shouldRotate bool
	}
	DescribeTable("nextRotationDeadlineForCert",
		func(c nextRotationDeadlineForCertCase) {
			notAfter := now.Add(c.notAfter)
			notBefore := now.Add(c.notBefore)
			caCert := &x509.Certificate{
				NotBefore: notBefore,
				NotAfter:  notAfter,
			}

			lowerBound := notBefore.Add(notAfter.Sub(notBefore) - c.overlap)

			deadline := nextRotationDeadlineForCert(caCert, c.overlap)

			Expect(deadline).To(Equal(lowerBound), fmt.Sprintf("should match deadline for notBefore %v, notAfter %v and overlap %v", notBefore, notAfter, c.overlap))

		},
		Entry("just issued, still good", nextRotationDeadlineForCertCase{
			notBefore:    -1 * time.Hour,
			notAfter:     99 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: false,
		}),
		Entry("half way expired, still good", nextRotationDeadlineForCertCase{
			notBefore:    -24 * time.Hour,
			notAfter:     24 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: false,
		}),
		Entry("mostly expired, still good", nextRotationDeadlineForCertCase{
			notBefore:    -69 * time.Hour,
			notAfter:     31 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: false,
		}),
		Entry("just about expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -91 * time.Hour,
			notAfter:     9 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: true,
		}),
		Entry("nearly expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -99 * time.Hour,
			notAfter:     1 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: true,
		}),
		Entry("already expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -10 * time.Hour,
			notAfter:     -1 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: true,
		}),
		Entry("long duration", nextRotationDeadlineForCertCase{
			notBefore:    -6 * 30 * 24 * time.Hour,
			notAfter:     6 * 30 * 24 * time.Hour,
			shouldRotate: true,
		}),
		Entry("short duration", nextRotationDeadlineForCertCase{
			notBefore:    -30 * time.Second,
			notAfter:     30 * time.Second,
			shouldRotate: true,
		}),
	)
})
