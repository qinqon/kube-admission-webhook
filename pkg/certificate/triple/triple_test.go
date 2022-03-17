/*
 * Copyright 2022 Kube Admission Webhook Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package triple

import (
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cert library", func() {
	Context("when NewCA is called", func() {
		var (
			name     string
			duration time.Duration
			now      time.Time
		)
		BeforeEach(func() {
			now = time.Now()
			name = "foo-bar-name"
			duration = time.Minute
			Now = func() time.Time { return now }
		})
		It("should generate key and CA cert with expected fields", func() {

			keyAndCert, err := NewCA(name, duration)
			Expect(err).ToNot(HaveOccurred(), "should succeed generating CA")

			privateKey := keyAndCert.Key
			caCert := keyAndCert.Cert

			Expect(privateKey).ToNot(BeNil(), "should generate a private key")
			Expect(caCert).ToNot(BeNil(), "should generate a CA certificate")
			Expect(caCert.SerialNumber.Int64()).To(Equal(int64(0)), "should have zero as serial number")
			Expect(caCert.Subject.CommonName).To(Equal(name), "should take CommonName from name field")
			Expect(caCert.NotBefore).To(BeTemporally("~", now.UTC(), time.Second), "should set NotBefore to now")
			Expect(caCert.NotAfter).To(BeTemporally("~", now.Add(duration).UTC(), time.Second), "should  set NotAfter to now + duration")
			Expect(caCert.KeyUsage).To(Equal(x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign),
				"should set proper KeyUsage")
			Expect(caCert.BasicConstraintsValid).To(BeTrue(), "should mark it as BasicConstraintsValid")
			Expect(caCert.IsCA).To(BeTrue(), "should mark it as CA")
			Expect(caCert.SubjectKeyId).ToNot(BeEmpty(), "should include a SKI")
		})

	})

	type removeOldestCertsParams struct {
		certsList         []*x509.Certificate
		maxListSize       int
		expectedCertsList []*x509.Certificate
	}
	certOldest := &x509.Certificate{
		NotBefore: time.Now().Add(10 * time.Hour),
		NotAfter:  time.Now(),
	}
	certOld := &x509.Certificate{
		NotBefore: time.Now().Add(5 * time.Hour),
		NotAfter:  time.Now(),
	}
	certCurrent := &x509.Certificate{
		NotBefore: time.Now(),
		NotAfter:  time.Now(),
	}

	DescribeTable("removeOldestCerts",
		func(c removeOldestCertsParams) {
			Expect(removeOldestCerts(c.certsList, c.maxListSize)).To(ConsistOf(c.expectedCertsList), "should remove the oldest certs")
		},
		Entry("when list is empty",
			removeOldestCertsParams{
				certsList:         []*x509.Certificate{},
				maxListSize:       2,
				expectedCertsList: []*x509.Certificate{},
			}),
		Entry("when list size is less or equal to max certs, should keep the certs list intact",
			removeOldestCertsParams{
				certsList:         []*x509.Certificate{certCurrent, certOld, certOldest},
				maxListSize:       3,
				expectedCertsList: []*x509.Certificate{certCurrent, certOld, certOldest},
			}),
		Entry("when list size is bigger than max certs, should remove the oldest certs",
			removeOldestCertsParams{
				certsList:         []*x509.Certificate{certCurrent, certOld, certOldest},
				maxListSize:       2,
				expectedCertsList: []*x509.Certificate{certCurrent, certOld},
			}),
	)
})
