package certificate

import (
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cleanup", func() {
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

	type earliestCleanupDeadlineCase struct {
		certsExpiration []certificateExpiration
		expectedElapsed time.Duration
	}
	DescribeTable("earliestCleanupDeadline",
		func(c earliestCleanupDeadlineCase) {

			m := Manager{
				now: func() time.Time { return now },
				log: log,
			}

			certificates := expirationsToCertificates(c.certsExpiration)

			obtainedDeadline := m.earliestCleanupDeadlineForCerts(certificates)
			obtainedElapsed := obtainedDeadline.Sub(now)
			Expect(obtainedElapsed).To(Equal(c.expectedElapsed))
		},
		Entry("empty certificates, deadline is now", earliestCleanupDeadlineCase{
			certsExpiration: []certificateExpiration{},
			expectedElapsed: time.Duration(0),
		}),
		Entry("one certificate, deadline is certificate's expiration time", earliestCleanupDeadlineCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  99 * time.Hour,
				},
			},
			expectedElapsed: 99 * time.Hour,
		}),
		Entry("first one sooner, deadline taken from it", earliestCleanupDeadlineCase{
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
		Entry("second one sooner, deadline taken from it", earliestCleanupDeadlineCase{
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
		Entry("third one sooner, deadline taken from it", earliestCleanupDeadlineCase{
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
	type cleanUpCertificatesCase struct {
		certsExpiration         []certificateExpiration
		expectedCertsExpiration []certificateExpiration
	}
	DescribeTable("cleanUpCertificates",
		func(c cleanUpCertificatesCase) {

			m := Manager{
				now: func() time.Time { return now },
				log: log,
			}

			certificates := expirationsToCertificates(c.certsExpiration)
			cleanedUpCertificates := m.cleanUpCertificates(certificates)
			expectedCertificates := expirationsToCertificates(c.expectedCertsExpiration)
			Expect(cleanedUpCertificates).To(Equal(expectedCertificates), "should have cleaned up certificates")

		},
		Entry("empty certificates do noop", cleanUpCertificatesCase{
			certsExpiration:         []certificateExpiration{},
			expectedCertsExpiration: []certificateExpiration{},
		}),
		Entry("contains just one certificate and it's not expired (there is no overlap happening), should keep it ", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -6 * time.Hour,
					notAfter:  11 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -6 * time.Hour,
					notAfter:  11 * time.Hour,
				},
			},
		}),
		Entry("none is expired, should keep them", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -2 * time.Hour,
					notAfter:  11 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -3 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -2 * time.Hour,
					notAfter:  11 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -3 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
		}),

		Entry("first one is expired, should remove it", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -5 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
				{
					notBefore: -3 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -3 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
		}),
		Entry("first expired long ago, should remove it", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -99 * time.Hour,
					notAfter:  -44 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  66 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  33 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  66 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  33 * time.Hour,
				},
			},
		}),
		Entry("middle one expired right now, should remove it", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  33 * time.Hour,
				},
				{
					notBefore: -5 * time.Hour,
					notAfter:  0 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  33 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
		}),
		Entry("middle one expired long ago, should remove it", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -99 * time.Hour,
					notAfter:  -44 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  33 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  33 * time.Hour,
				},
			},
		}),
		Entry("last one expired long ago, should remove it", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  80 * time.Hour,
				},
				{
					notBefore: -34 * time.Hour,
					notAfter:  -90 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  80 * time.Hour,
				},
			},
		}),
		Entry("One certificate expired now, should remove it", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -3 * time.Hour,
					notAfter:  0,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  1 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  1 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -2 * time.Hour,
					notAfter:  1 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  1 * time.Hour,
				},
			},
		}),

		Entry("All expired, should remove all of them", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -3 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
				{
					notBefore: -1 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{},
		}),
		Entry("first one is expired, should remove it", cleanUpCertificatesCase{
			certsExpiration: []certificateExpiration{
				{
					notBefore: -5 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
				{
					notBefore: -3 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -3 * time.Hour,
					notAfter:  99 * time.Hour,
				},
				{
					notBefore: -2 * time.Hour,
					notAfter:  101 * time.Hour,
				},
			},
		}),
	)
})
