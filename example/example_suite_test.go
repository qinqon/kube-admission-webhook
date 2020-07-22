package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var (
	testEnv *envtest.Environment
	cfg     *rest.Config
	cli     client.Client
	//TODO: Read it from flag or put true if we have a
	//      KUBECONFIG env var
	useCluster = false
)

var _ = BeforeSuite(func() {

	logf.SetLogger(zap.LoggerTo(GinkgoWriter, true))

	testEnv = &envtest.Environment{
		UseExistingCluster: &useCluster,
	}

	/*
		cfg, err := testEnv.Start()
		Expect(err).ToNot(HaveOccurred(), "should success starting testenv")

		cli, err = client.New(cfg, client.Options{})
		Expect(err).ToNot(HaveOccurred(), "should success creating client")
	*/

})

var _ = AfterSuite(func() {

	/*
		err := testEnv.Stop()
		Expect(err).ToNot(HaveOccurred(), "should success stopping testenv")
	*/
})

func TestServer(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit.example.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Example Test Suite", []Reporter{junitReporter, printer.NewlineReporter{}})
}
