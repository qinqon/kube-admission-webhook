package triple

import (
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cert library", func() {

	type removeOldestCertsParams struct {
		certsList         []*x509.Certificate
		maxListSize       int
		expectedCertsList []*x509.Certificate
	}
	certOldest := &x509.Certificate{
		NotBefore: time.Now().Add(10*time.Hour),
		NotAfter:  time.Now(),
	}
	certOld := &x509.Certificate{
		NotBefore: time.Now().Add(5*time.Hour),
		NotAfter:  time.Now(),
	}
	certCurrent := &x509.Certificate{
		NotBefore: time.Now(),
		NotAfter:  time.Now(),
	}

	DescribeTable("removeOldestCerts",
		func(c removeOldestCertsParams) {
			Expect(RemoveOldestCerts(c.certsList, c.maxListSize)).To(ConsistOf(c.expectedCertsList), "should remove the oldest certs")
		},
		Entry("when list is empty",
			removeOldestCertsParams{
				certsList:         []*x509.Certificate{},
				maxListSize:       2,
				expectedCertsList: []*x509.Certificate{},
			}),
		Entry("when list size is less or equal to max certs, should keep the certs list intact",
			removeOldestCertsParams{
				certsList:         []*x509.Certificate{certOldest, certOld, certCurrent},
				maxListSize:        3,
				expectedCertsList: []*x509.Certificate{certOldest, certOld, certCurrent},
			}),
		Entry("when list size is bigger than max certs, should remove the oldest certs",
			removeOldestCertsParams{
				certsList:         []*x509.Certificate{certOldest, certOld, certCurrent},
				maxListSize:       2,
				expectedCertsList: []*x509.Certificate{certOld, certCurrent},
			}),
	)
})
