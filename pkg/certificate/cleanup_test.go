package certificate

import (
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("CABundle cleanup", func() {
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
		caOverlapDuration time.Duration
		certsExpiration   []certificateExpiration
		expectedElapsed   time.Duration
	}
	DescribeTable("earliestCleanupDeadline",
		func(c earliestCleanupDeadlineCase) {

			m := Manager{
				caOverlapDuration: c.caOverlapDuration,
				now:               func() time.Time { return now },
				log:               log,
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
			caOverlapDuration: 5 * time.Hour,
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  99 * time.Hour,
				},
			},
			expectedElapsed: 99 * time.Hour,
		}),
		Entry("first one sooner, deadline taken from it", earliestCleanupDeadlineCase{
			caOverlapDuration: 5 * time.Hour,
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
			expectedElapsed: 2 * time.Hour,
		}),
		Entry("second one sooner, deadline taken from it", earliestCleanupDeadlineCase{
			caOverlapDuration: 5 * time.Hour,
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
			expectedElapsed: 1 * time.Hour,
		}),
		Entry("third one sooner, deadline taken from it", earliestCleanupDeadlineCase{
			caOverlapDuration: 5 * time.Hour,
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
			expectedElapsed: 3 * time.Hour,
		}),
	)
	type cleanUpCertificatesCase struct {
		caOverlapDuration       time.Duration
		certsExpiration         []certificateExpiration
		expectedCertsExpiration []certificateExpiration
	}
	DescribeTable("cleanUpCertificates",
		func(c cleanUpCertificatesCase) {

			m := Manager{
				now:               func() time.Time { return now },
				log:               log,
				caOverlapDuration: c.caOverlapDuration,
			}

			certificates := expirationsToCertificates(c.certsExpiration)
			cleanedUpCertificates := m.cleanUpCertificates(certificates)
			expectedCertificates := expirationsToCertificates(c.expectedCertsExpiration)
			Expect(cleanedUpCertificates).To(Equal(expectedCertificates), "should have cleaned up certificates")

		},
		Entry("empty caBundle do noop", cleanUpCertificatesCase{
			certsExpiration:         []certificateExpiration{},
			expectedCertsExpiration: []certificateExpiration{},
		}),
		Entry("contains just one certificate and its beyond overlap duration (there is no overlap happening), should keep it ", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
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
		Entry("none beyond overlap duration, should keep them", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
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

		Entry("first one is beyond overlap duration right now, should remove it", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
			certsExpiration: []certificateExpiration{
				{
					notBefore: -5 * time.Hour,
					notAfter:  33 * time.Hour,
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
		Entry("first one beyond overlap duration long ago, should remove it", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
			certsExpiration: []certificateExpiration{
				{
					notBefore: -99 * time.Hour,
					notAfter:  44 * time.Hour,
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
		Entry("middle one beyond overlap duration right now, should remove it", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  33 * time.Hour,
				},
				{
					notBefore: -5 * time.Hour,
					notAfter:  44 * time.Hour,
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
		Entry("middle one beyond overlap duration long ago, should remove it", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
			certsExpiration: []certificateExpiration{
				{
					notBefore: -1 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -99 * time.Hour,
					notAfter:  44 * time.Hour,
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
		Entry("last one beyond overlap duration long ago, should keep it", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
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
					notAfter:  90 * time.Hour,
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
				{
					notBefore: -34 * time.Hour,
					notAfter:  90 * time.Hour,
				},
			},
		}),
		Entry("All beyond overlap duration, should keep the latest appended", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
			certsExpiration: []certificateExpiration{
				{
					notBefore: -7 * time.Hour,
					notAfter:  77 * time.Hour,
				},
				{
					notBefore: -8 * time.Hour,
					notAfter:  80 * time.Hour,
				},
				{
					notBefore: -34 * time.Hour,
					notAfter:  90 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{
				{
					notBefore: -34 * time.Hour,
					notAfter:  90 * time.Hour,
				},
			},
		}),
		Entry("All expired, should remove all of them", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
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
		Entry("All expired and beyond limit, should remove all of them", cleanUpCertificatesCase{
			caOverlapDuration: 5 * time.Hour,
			certsExpiration: []certificateExpiration{
				{
					notBefore: -6 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
				{
					notBefore: -7 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
				{
					notBefore: -8 * time.Hour,
					notAfter:  -1 * time.Hour,
				},
			},
			expectedCertsExpiration: []certificateExpiration{},
		}),
	)
})
