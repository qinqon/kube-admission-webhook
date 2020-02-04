package server

import (
	"testing"

	certificate "github.com/qinqon/kube-admission-webhook/pkg/webhook/server/certificate"
)

func TestStuff(t *testing.T) {
	_ = New(nil, "foo", certificate.MutatingWebhook)
}
