package chain

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certificate Options", func() {
	type setDefaultsAndValidateCase struct {
		options         Options
		expectedOptions Options
		isValid         bool
	}
	DescribeTable("SetDefaultsAndValidate",
		func(c setDefaultsAndValidateCase) {
			err := c.options.SetDefaultsAndValidate()
			if c.isValid {
				Expect(err).To(Succeed(), "should succeed validating the options")
			} else {
				Expect(err).ToNot(Succeed(), "should not succeed validating the options")
			}
			Expect(c.options).To(Equal(c.expectedOptions), "should equal expected options after setting defaults")
		},
		Entry("Empty options should be valid", setDefaultsAndValidateCase{
			expectedOptions: Options{
				CARotateInterval:    OneYearDuration,
				CAOverlapInterval:   OneYearDuration,
				CertRotateInterval:  OneYearDuration,
				CertOverlapInterval: OneYearDuration,
			},
			isValid: true,
		}),
		Entry("CAOverlapInterval has to default to CARotateInterval", setDefaultsAndValidateCase{
			options: Options{
				CARotateInterval: 2 * OneYearDuration,
			},
			expectedOptions: Options{
				CARotateInterval:    2 * OneYearDuration,
				CAOverlapInterval:   2 * OneYearDuration,
				CertRotateInterval:  2 * OneYearDuration,
				CertOverlapInterval: 2 * OneYearDuration,
			},
			isValid: true,
		}),
		Entry("CertRotateInterval has to default to CARotateInterval", setDefaultsAndValidateCase{
			options: Options{
				CARotateInterval:  2 * OneYearDuration,
				CAOverlapInterval: 1 * OneYearDuration,
			},
			expectedOptions: Options{
				CARotateInterval:    2 * OneYearDuration,
				CAOverlapInterval:   1 * OneYearDuration,
				CertRotateInterval:  2 * OneYearDuration,
				CertOverlapInterval: 2 * OneYearDuration,
			},
			isValid: true,
		}),
		Entry("CertOverlapInterval has to default to CertRotateInterval", setDefaultsAndValidateCase{
			options: Options{
				CARotateInterval:   2 * OneYearDuration,
				CAOverlapInterval:  1 * OneYearDuration,
				CertRotateInterval: OneYearDuration / 2,
			},
			expectedOptions: Options{
				CARotateInterval:    2 * OneYearDuration,
				CAOverlapInterval:   1 * OneYearDuration,
				CertRotateInterval:  OneYearDuration / 2,
				CertOverlapInterval: OneYearDuration / 2,
			},
			isValid: true,
		}),

		Entry("Passing CAOverlapInterval > CARotateInterval should be invalid", setDefaultsAndValidateCase{
			options: Options{
				CARotateInterval:  1 * time.Hour,
				CAOverlapInterval: 2 * time.Hour,
			},
			expectedOptions: Options{
				CARotateInterval:  1 * time.Hour,
				CAOverlapInterval: 2 * time.Hour,
			},
			isValid: false,
		}),
		Entry("Passing CertRotateInterval > CARotateInterval should be invalid", setDefaultsAndValidateCase{
			options: Options{
				CARotateInterval:   1 * time.Hour,
				CertRotateInterval: 2 * time.Hour,
			},
			expectedOptions: Options{
				CARotateInterval:   1 * time.Hour,
				CertRotateInterval: 2 * time.Hour,
			},
			isValid: false,
		}),
		Entry("Passing CertOverlapInterval > CertRotateInterval should be invalid", setDefaultsAndValidateCase{
			options: Options{
				CertRotateInterval:  1 * time.Hour,
				CertOverlapInterval: 2 * time.Hour,
			},
			expectedOptions: Options{
				CertRotateInterval:  1 * time.Hour,
				CertOverlapInterval: 2 * time.Hour,
			},
			isValid: false,
		}),

		Entry("Passing all options override defaults", setDefaultsAndValidateCase{
			options: Options{
				CARotateInterval:    1 * time.Hour,
				CAOverlapInterval:   1 * time.Minute,
				CertRotateInterval:  30 * time.Minute,
				CertOverlapInterval: 15 * time.Minute,
			},
			expectedOptions: Options{
				CARotateInterval:    1 * time.Hour,
				CAOverlapInterval:   1 * time.Minute,
				CertRotateInterval:  30 * time.Minute,
				CertOverlapInterval: 15 * time.Minute,
			},
			isValid: true,
		}),
	)
})
