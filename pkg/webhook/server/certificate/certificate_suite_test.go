package certificate

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var (
	testEnv   *envtest.Environment
	cli       client.Client
	namespace = corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foowebhook",
		},
	}
	//TODO: Read it from flag or put true if we have a
	//      KUBECONFIG env var
	useCluster = false
)

var _ = BeforeSuite(func() {

	testEnv = &envtest.Environment{
		UseExistingCluster: &useCluster,
	}

	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred(), "should success starting testenv")

	cli, err = client.New(cfg, client.Options{})
	Expect(err).ToNot(HaveOccurred(), "should success creating client")

	// Ideally we create/delete the namespace at every test but, envtest
	// cannot delete namespaces [1] so we just create it at the beggining
	// of the test suite.
	//
	// [1] https://book.kubebuilder.io/reference/testing/envtest.html?highlight=envtest#testing-considerations
	By("Create namespace, webhook configuration and service")
	err = cli.Create(context.TODO(), &namespace)
	Expect(err).ToNot(HaveOccurred(), "should success creating namespace")

})

var _ = AfterSuite(func() {

	if useCluster {
		err := cli.Delete(context.TODO(), &namespace)
		Expect(err).ToNot(HaveOccurred(), "should success deleting namespace")
	}

	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred(), "should success stopping testenv")
})

func init() {
	klog.InitFlags(nil)
	logf.SetLogger(logf.ZapLogger(true))
}

func TestUnit(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit.certificate_suite_test.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Certificate Test Suite", []Reporter{junitReporter})
}
