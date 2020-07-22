package main

import (
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("kube-webhook-admission example", func() {
	It("should run", func() {
		command := exec.Command(filepath.Join(os.Getenv("BIN_DIR"), "example"))
		session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
		Expect(err).To(Succeed(), "should succeed starting example")
		Expect(session).ToNot(gexec.Exit(), "example should not exit")
	})
})
