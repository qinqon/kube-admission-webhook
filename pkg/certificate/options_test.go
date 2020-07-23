package certificate

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
	DescribeTable("setDefaultsAndValidate",
		func(c setDefaultsAndValidateCase) {
			err := c.options.setDefaultsAndValidate()
			if c.isValid {
				Expect(err).To(Succeed(), "should succeed validating the options")
			} else {
				Expect(err).ToNot(Succeed(), "should not succeed validating the options")
			}
			Expect(c.options).To(Equal(c.expectedOptions), "should equal expected options after setting defaults")
		},
		Entry("Empty options should be invalid since it's missing webhook name and namespace and set defaults", setDefaultsAndValidateCase{
			isValid: false,
		}),
		Entry("Just passing webhook name options should be invalid since it's missing namespace and set default", setDefaultsAndValidateCase{
			options: Options{
				WebhookName: "MyWebhook",
			},
			expectedOptions: Options{
				WebhookName: "MyWebhook",
			},
			isValid: false,
		}),
		Entry("Passing webhook name and namespace options should be valid and set default", setDefaultsAndValidateCase{
			options: Options{
				Namespace:   "MyNamespace",
				WebhookName: "MyWebhook",
			},
			expectedOptions: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				WebhookType:        MutatingWebhook,
				CARotateInterval:   OneYearDuration,
				CAOverlapInterval:  OneYearDuration,
				CertRotateInterval: OneYearDuration,
			},
			isValid: true,
		}),
		Entry("Passing WebhookType ValidatingWebhook options should be valid", setDefaultsAndValidateCase{
			options: Options{
				Namespace:   "MyNamespace",
				WebhookName: "MyWebhook",
				WebhookType: ValidatingWebhook,
			},
			expectedOptions: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				WebhookType:        ValidatingWebhook,
				CARotateInterval:   OneYearDuration,
				CAOverlapInterval:  OneYearDuration,
				CertRotateInterval: OneYearDuration,
			},
			isValid: true,
		}),
		Entry("Passing WebhookType MutatingWebhook options should be valid", setDefaultsAndValidateCase{
			options: Options{
				Namespace:   "MyNamespace",
				WebhookName: "MyWebhook",
				WebhookType: MutatingWebhook,
			},
			expectedOptions: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				WebhookType:        MutatingWebhook,
				CARotateInterval:   OneYearDuration,
				CAOverlapInterval:  OneYearDuration,
				CertRotateInterval: OneYearDuration,
			},
			isValid: true,
		}),
		Entry("Passing unknown WebhookType should be invalid", setDefaultsAndValidateCase{
			options: Options{
				Namespace:   "MyNamespace",
				WebhookName: "MyWebhook",
				WebhookType: "BadWebhookType",
			},
			expectedOptions: Options{
				Namespace:   "MyNamespace",
				WebhookName: "MyWebhook",
				WebhookType: "BadWebhookType",
			},
			isValid: false,
		}),
		Entry("CAOverlapInterval has to default to CARotateInterval", setDefaultsAndValidateCase{
			options: Options{
				Namespace:        "MyNamespace",
				WebhookName:      "MyWebhook",
				CARotateInterval: 2 * OneYearDuration,
			},
			expectedOptions: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				WebhookType:        MutatingWebhook,
				CARotateInterval:   2 * OneYearDuration,
				CAOverlapInterval:  2 * OneYearDuration,
				CertRotateInterval: 2 * OneYearDuration,
			},
			isValid: true,
		}),
		Entry("CertRotateInterval has to default to CARotateInterval", setDefaultsAndValidateCase{
			options: Options{
				Namespace:         "MyNamespace",
				WebhookName:       "MyWebhook",
				CARotateInterval:  2 * OneYearDuration,
				CAOverlapInterval: 1 * OneYearDuration,
			},
			expectedOptions: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				WebhookType:        MutatingWebhook,
				CARotateInterval:   2 * OneYearDuration,
				CAOverlapInterval:  1 * OneYearDuration,
				CertRotateInterval: 2 * OneYearDuration,
			},
			isValid: true,
		}),
		Entry("Passing CAOverlapInterval > CARotateInterval should be invalid", setDefaultsAndValidateCase{
			options: Options{
				Namespace:         "MyNamespace",
				WebhookName:       "MyWebhook",
				CARotateInterval:  1 * time.Hour,
				CAOverlapInterval: 2 * time.Hour,
			},
			expectedOptions: Options{
				Namespace:         "MyNamespace",
				WebhookName:       "MyWebhook",
				CARotateInterval:  1 * time.Hour,
				CAOverlapInterval: 2 * time.Hour,
			},
			isValid: false,
		}),
		Entry("Passing CertRotateInterval > CARotateInterval should be invalid", setDefaultsAndValidateCase{
			options: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				CARotateInterval:   1 * time.Hour,
				CertRotateInterval: 2 * time.Hour,
			},
			expectedOptions: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				CARotateInterval:   1 * time.Hour,
				CertRotateInterval: 2 * time.Hour,
			},
			isValid: false,
		}),
		Entry("Passing all options override defaults", setDefaultsAndValidateCase{
			options: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				WebhookType:        ValidatingWebhook,
				CARotateInterval:   1 * time.Hour,
				CAOverlapInterval:  1 * time.Minute,
				CertRotateInterval: 30 * time.Minute,
			},
			expectedOptions: Options{
				Namespace:          "MyNamespace",
				WebhookName:        "MyWebhook",
				WebhookType:        ValidatingWebhook,
				CARotateInterval:   1 * time.Hour,
				CAOverlapInterval:  1 * time.Minute,
				CertRotateInterval: 30 * time.Minute,
			},
			isValid: true,
		}),
	)
})
