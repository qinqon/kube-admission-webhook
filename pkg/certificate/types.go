package certificate

import (
	"fmt"
)

type WebhookType string

const (
	MutatingWebhook   WebhookType = "Mutating"
	ValidatingWebhook WebhookType = "Validating"
)

type WebhookReference struct {
	Type WebhookType
	Name string
}

func (w WebhookReference) String() string {
	return fmt.Sprintf("%sWebhook/%s", w.Type, w.Name)
}
