package tls

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Testing TLS Security Profile", func() {
	type loadSecurityProfileCase struct {
		securityProfile       *TLSSecurityProfile
		expectedCiphers       []string
		expectedMinTLSVersion TLSProtocolVersion
	}
	testCustomTLSProfileSpec := TLSProfileSpec{
		Ciphers:       []string{"foo,bar"},
		MinTLSVersion: "foobar",
	}
	DescribeTable("SecurityProfileSpec function",
		func(c loadSecurityProfileCase) {
			ciphers, minTLSVersion := SecurityProfileSpec(c.securityProfile)
			Expect(ciphers).To(Equal(c.expectedCiphers))
			Expect(minTLSVersion).To(Equal(c.expectedMinTLSVersion))
		},
		Entry("when TLSSecurityProfile is nil", loadSecurityProfileCase{
			securityProfile:       nil,
			expectedCiphers:       []string{},
			expectedMinTLSVersion: "",
		}),
		Entry("when Old Security Profile is selected", loadSecurityProfileCase{
			securityProfile: &TLSSecurityProfile{
				Type: TLSProfileOldType,
				Old:  &OldTLSProfile{},
			},
			expectedCiphers:       TLSProfiles[TLSProfileOldType].Ciphers,
			expectedMinTLSVersion: TLSProfiles[TLSProfileOldType].MinTLSVersion,
		}),
		Entry("when Intermediate Security Profile is selected", loadSecurityProfileCase{
			securityProfile: &TLSSecurityProfile{
				Type:         TLSProfileIntermediateType,
				Intermediate: &IntermediateTLSProfile{},
			},
			expectedCiphers:       TLSProfiles[TLSProfileIntermediateType].Ciphers,
			expectedMinTLSVersion: TLSProfiles[TLSProfileIntermediateType].MinTLSVersion,
		}),
		Entry("when Custom Security Profile is selected", loadSecurityProfileCase{
			securityProfile: &TLSSecurityProfile{
				Type: TLSProfileCustomType,
				Custom: &CustomTLSProfile{
					TLSProfileSpec: testCustomTLSProfileSpec,
				},
			},
			expectedCiphers:       testCustomTLSProfileSpec.Ciphers,
			expectedMinTLSVersion: testCustomTLSProfileSpec.MinTLSVersion,
		}),
	)
})
