package server

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	certificate "github.com/qinqon/kube-admission-webhook/pkg/webhook/server/certificate"
)

var _ = Describe("Server", func() {
	Context("when constructor is called", func() {
		It("should return a sever", func() {
			server := New(nil, "foo", certificate.MutatingWebhook)
			Expect(server).ToNot(BeNil())
		})
	})
})
