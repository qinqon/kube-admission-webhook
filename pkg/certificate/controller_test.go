package certificate

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var (
	log = logf.Log.WithName("certificate/manager_test")
)

var _ = Describe("Certificates controller", func() {

	Context("when reconcile is called", func() {
		BeforeEach(createResources)
		AfterEach(deleteResources)
		It("should rotate certificates", func() {

			type TLS struct {
				caBundle, certificate, privateKey []byte
			}

			getTLS := func() TLS {
				obtainedWebhookConfiguration := admissionregistrationv1beta1.MutatingWebhookConfiguration{}
				err := cli.Get(context.TODO(), types.NamespacedName{Name: "foowebhook"}, &obtainedWebhookConfiguration)
				Expect(err).To(Succeed(), "should success getting mutatingwebhookconfiguration")

				cliConfig := obtainedWebhookConfiguration.Webhooks[0].ClientConfig
				Expect(cliConfig.CABundle).ToNot(BeEmpty(), "should update CA budle")

				obtainedSecret := corev1.Secret{}
				err = cli.Get(context.TODO(), types.NamespacedName{Name: expectedSecret.Name, Namespace: expectedSecret.Namespace}, &obtainedSecret)
				Expect(err).ToNot(HaveOccurred(), "should success getting secret")
				Expect(obtainedSecret.Type).To(Equal(corev1.SecretTypeTLS), "should be a TLS secret")
				Expect(obtainedSecret.Data).ToNot(BeEmpty(), "should contain a secret with TLS key/cert")

				return TLS{
					caBundle:    cliConfig.CABundle,
					certificate: expectedSecret.Data[corev1.TLSCertKey],
					privateKey:  expectedSecret.Data[corev1.TLSPrivateKeyKey]}
			}

			certsDuration := 256 * 24 * time.Hour
			manager := NewManager(cli, "foowebhook", MutatingWebhook, certsDuration)

			// Freeze time
			now := time.Now()
			manager.now = func() time.Time { return now }

			// First call for reconcile
			firstTimeResponse, err := manager.Reconcile(reconcile.Request{})
			Expect(err).To(Succeed(), "should success reconciling")
			Expect(firstTimeResponse.RequeueAfter).To(BeNumerically("<", certsDuration), "should requeue before expiration time")

			firstTimeTLS := getTLS()

			// Call Reconcile in the middle of certsDuration
			manager.now = func() time.Time { return now.Add(certsDuration / 2) }
			middleTimeResponse, err := manager.Reconcile(reconcile.Request{})
			Expect(err).To(Succeed(), "should success reconciling")
			Expect(middleTimeResponse.RequeueAfter).To(BeNumerically(">=", firstTimeResponse.RequeueAfter, "should subsctract 'now' from deadline at reconcile in the middle of certificate duration"))

			middleTimeTLS := getTLS()

			Expect(middleTimeTLS).To(Equal(firstTimeTLS), "should not change TLS cert/key on reconcile in the middle of certificate duration")

			By("Callint Reconcile at 90%% of certificates duration they should be rotated")
			manager.now = func() time.Time { return now.Add(time.Duration(float64(certsDuration) * 0.9)) }
			deadlineResponse, err := manager.Reconcile(reconcile.Request{})
			Expect(err).To(Succeed(), "should success reconciling")

			Expect(deadlineResponse.RequeueAfter).To(BeNumerically(">", firstTimeResponse.RequeueAfter, "Second Reconcile not substracting now to deadline"))

			deadlineTimeTLS := getTLS()
			Expect(deadlineTimeTLS).ToNot(Equal(firstTimeTLS), "should rotate TLS cert/key on Reconcile after deadline")
		})
	})
})
