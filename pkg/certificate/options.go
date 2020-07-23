package certificate

import (
	"time"
)

type WebhookType string

const (
	MutatingWebhook   WebhookType = "Mutating"
	ValidatingWebhook WebhookType = "Validating"
	OneYearDuration               = 365 * 24 * time.Hour
)

type Options struct {

	// webhookName The Mutating or Validating Webhook configuration name
	WebhookName string

	// webhookType The Mutating or Validating Webhook configuration type
	WebhookType WebhookType

	// The namespace where ca secret will be created or service secrets
	// for ClientConfig that has URL instead of ServiceRef
	Namespace string

	// CARotateInterval configurated duration for CA and certificate
	CARotateInterval time.Duration

	// CertRotateInterval configurated duration for of service certificate
	// the the webhook configuration is referencing different services all
	// of them will share the same duration
	CertRotateInterval time.Duration
}

func (o *Options) setDefaults() {

	if o.WebhookType == "" {
		o.WebhookType = MutatingWebhook
	}

	if o.CARotateInterval == 0 {
		o.CARotateInterval = OneYearDuration
	}

	if o.CertRotateInterval == 0 {
		o.CertRotateInterval = o.CARotateInterval
	}
}
