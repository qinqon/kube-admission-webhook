package certificate

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var (
	testEnv *envtest.Environment
	cli     client.Client
	//TODO: Read it from flag or put true if we have a
	//      KUBECONFIG env var
	useCluster = false

	expectedNamespace = corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foowebhook",
		},
	}

	expectedService = corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "foowebhook",
			Name:      "foowebhook-service",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "https",
					Port: 8443,
				},
			},
		},
	}

	expectedMutatingWebhookConfiguration = admissionregistrationv1beta1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foowebhook",
		},
		Webhooks: []admissionregistrationv1beta1.MutatingWebhook{
			admissionregistrationv1beta1.MutatingWebhook{
				Name: "foowebhook.qinqon.io",
				ClientConfig: admissionregistrationv1beta1.WebhookClientConfig{
					Service: &admissionregistrationv1beta1.ServiceReference{
						Name:      expectedService.Name,
						Namespace: expectedService.Namespace,
					},
				},
			},
		},
	}

	expectedSecret = corev1.Secret{
		ObjectMeta: expectedService.ObjectMeta,
	}

	expectedCASecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      expectedMutatingWebhookConfiguration.Name,
		},
	}
)

func createResources() {
	err := cli.Create(context.TODO(), expectedMutatingWebhookConfiguration.DeepCopy())
	ExpectWithOffset(1, err).ToNot(HaveOccurred(), "should success creating mutatingwebhookconfiguration")

	err = cli.Create(context.TODO(), expectedService.DeepCopy())
	ExpectWithOffset(1, err).ToNot(HaveOccurred(), "should success creating service")
}

func deleteResources() {
	_ = cli.Delete(context.TODO(), &expectedMutatingWebhookConfiguration)
	_ = cli.Delete(context.TODO(), &expectedService)
	_ = cli.Delete(context.TODO(), &expectedSecret)
}

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
	err = cli.Create(context.TODO(), &expectedNamespace)
	Expect(err).ToNot(HaveOccurred(), "should success creating namespace")

})

var _ = AfterSuite(func() {

	if useCluster {
		err := cli.Delete(context.TODO(), &expectedNamespace)
		Expect(err).ToNot(HaveOccurred(), "should success deleting namespace")
	}

	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred(), "should success stopping testenv")
})

func init() {
	klog.InitFlags(nil)
	logf.SetLogger(logf.ZapLogger(true))
}

func TestCertificate(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit.certificate_suite_test.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Certificate Test Suite", []Reporter{junitReporter})
}
