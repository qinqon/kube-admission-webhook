package chain

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

var _ = Describe("chain", func() {
	const (
		caName        = "foo-ca"
		certIssueName = "foo-service"
		caCertName    = "foo-webhook"
	)

	type verifyTLSTestCase struct {
		certificateChainMod func(chain *CertificateChainData)
		shouldFail       bool
	}

	DescribeTable("VerifyTLS on a certificate chain",
		func(t verifyTLSTestCase) {
			options := Options{}
			chain := CertificateChainData{
				CertificatesIssued: map[string]*CertificateIssue{
					certIssueName: {
						Name:      certIssueName,
						Hostnames: []string{certIssueName},
						CACertPEM: map[string][]byte{
							caCertName: {},
						},
					},
				},
				CA: CA{
					Name: caName,
				},
			}
			c, err := newChain(&options, &chain)
			Expect(err).To(Succeed(), "initial chain data should be valid")
			_, err = c.update()
			Expect(err).To(Succeed(), "should initially reconcile")
			t.certificateChainMod(&chain)
			c, err = newChain(&options, &chain)
			Expect(err).To(Succeed(), "modified chain data should be valid")
			err = c.verifyTLS()
			if t.shouldFail {
				Expect(err).To(HaveOccurred(), "should fail VerifyTLS")
			} else {
				Expect(err).To(Succeed(), "should success VerifyTLS")
			}
		},
		Entry("after rotate, should not fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {},
			shouldFail:       false,
		}),
		Entry("missing a key, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CertificatesIssued[certIssueName].KeyPEM = nil
			},
			shouldFail: true,
		}),
		Entry("missing a cert, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CertificatesIssued[certIssueName].CertPEM = nil
			},
			shouldFail: true,
		}),
		Entry("missing CA key, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CA.KeyPEM = nil
			},
			shouldFail: true,
		}),
		Entry("missing CA cert, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CA.CertPEM = nil
			},
			shouldFail: true,
		}),
		Entry("when private key is not PEM, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CertificatesIssued[certIssueName].KeyPEM = []byte("This is not a PEM encoded key")
			},
			shouldFail: true,
		}),
		Entry("when certificate is not PEM, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CertificatesIssued[certIssueName].CertPEM = []byte("This is not a PEM encoded key")
			},
			shouldFail: true,
		}),
		Entry("when CA's private key is not PEM, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CA.KeyPEM = []byte("This is not a PEM encoded key")
			},
			shouldFail: true,
		}),
		Entry("when CA's certificate is not PEM, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CA.CertPEM = []byte("This is not a PEM encoded key")
			},
			shouldFail: true,
		}),
		Entry("missing CA cert for verification, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CertificatesIssued[certIssueName].CACertPEM[caCertName] = nil
			},
			shouldFail: true,
		}),
		Entry("when CA cert for verification is not PEM formated, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				chain.CertificatesIssued[certIssueName].CACertPEM[caCertName] = []byte("This is not a CABundle PEM")
			},
			shouldFail: true,
		}),
		Entry("when last CA cert for verification is not the same as current CA cert, should fail", verifyTLSTestCase{
			certificateChainMod: func(chain *CertificateChainData) {
				hackedCA, err := triple.NewCA("hacked-ca", 100*365*24*time.Hour)
				Expect(err).To(Succeed(), "should succeed creating new hacked CA")
				caBundle := chain.CertificatesIssued[certIssueName].CACertPEM[caCertName]
				hackedCABundle := append(caBundle, triple.EncodeCertPEM(hackedCA.Cert)...)
				chain.CertificatesIssued[certIssueName].CACertPEM[caCertName] = hackedCABundle
			},
			shouldFail: true,
		}),
	)
})
