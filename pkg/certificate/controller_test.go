package certificate

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

var (
	log = logf.Log.WithName("certificate/manager_test")
)

var _ = Describe("Certificates controller", func() {
	var (
		certsDuration           = 256 * 24 * time.Hour
		mgr                     *Manager
		now                     time.Time
		isTLSEventuallyVerified = func() AsyncAssertion {
			return Eventually(func() error {
				return mgr.verifyTLS()
			}, 5*time.Second, 1*time.Second)
		}

		isTLSSecretEventuallyPresent = func() AsyncAssertion {
			return Eventually(func() (bool, error) {
				obtainedSecret := corev1.Secret{}
				err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedSecret.Namespace, Name: expectedSecret.Name}, &obtainedSecret)
				if err != nil {
					if apierrors.IsNotFound(err) {
						return false, nil
					}
					return false, err
				}
				return true, nil
			}, 5*time.Second, 1*time.Second)
		}
	)

	BeforeEach(func() {

		mgr = NewManager(cli, "foowebhook", MutatingWebhook, certsDuration)

		// Freeze time
		now = time.Now()

		createResources()
	})

	AfterEach(func() {
		deleteResources()
	})
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
	Context("when reconcile is called for the fist time", func() {
		var (
			previousResult, currentResult reconcile.Result
			previousTLS, currentTLS       TLS
		)
		BeforeEach(func() {
			mgr.now = func() time.Time { return now }
			triple.Now = mgr.now
			var err error
			currentResult, err = mgr.Reconcile(reconcile.Request{})
			Expect(err).To(Succeed(), "should success reconciling")
			previousTLS = getTLS()
		})

		It("should create TLS cert/key and return proper deadline", func() {
			// First call for reconcile
			Expect(currentResult.RequeueAfter).To(BeNumerically("<", certsDuration), "should requeue before expiration time")
		})
		Context("and then called in the middle of the deadline", func() {
			BeforeEach(func() {
				previousResult = currentResult
				mgr.now = func() time.Time { return now.Add(certsDuration / 2) }
				triple.Now = mgr.now
				var err error
				currentResult, err = mgr.Reconcile(reconcile.Request{})
				Expect(err).To(Succeed(), "should success reconciling")

				currentTLS = getTLS()
			})
			It("should not rotate and return a reduced deadline", func() {
				Expect(currentResult.RequeueAfter).To(BeNumerically("<", previousResult.RequeueAfter), "should subsctract 'now' from deadline at reconcile in the middle of certificate duration")
				Expect(currentTLS).To(Equal(previousTLS), "should not change TLS cert/key on reconcile in the middle of certificate duration")
			})

			Context("and finally called after 90%% of deadline", func() {
				BeforeEach(func() {
					previousTLS = currentTLS
					previousResult = currentResult
					mgr.now = func() time.Time { return now.Add(time.Duration(float64(certsDuration) * 0.9)) }
					triple.Now = mgr.now
					var err error
					currentResult, err = mgr.Reconcile(reconcile.Request{})
					Expect(err).To(Succeed(), "should success reconciling")
					currentTLS = getTLS()
				})
				It("should rotate TLS cert/key and return a new deadline", func() {
					Expect(currentTLS).ToNot(Equal(previousTLS), "should rotate TLS cert/key on Reconcile after deadline")
					Expect(currentResult.RequeueAfter).To(BeNumerically(">", previousResult.RequeueAfter), "Second Reconcile not substracting now to deadline")
				})
			})
		})
	})
	Context("when integrated into a controller-runtime manager and started", func() {
		var (
			crManager manager.Manager
			stopCh    chan struct{}
		)
		BeforeEach(func(done Done) {

			By("Creating new controller-runtime manager")
			var err error
			crManager, err = manager.New(testEnv.Config, manager.Options{Namespace: expectedNamespace.Name, MetricsBindAddress: "0"})
			Expect(err).ToNot(HaveOccurred(), "should success creating controller-runtime manager")

			err = mgr.Add(crManager)
			Expect(err).To(Succeed(), "should succeed adding the cert manager controller to the controller-runtime manager")

			By("Starting controller-runtime manager")
			stopCh = make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err = crManager.Start(stopCh)
				Expect(err).To(Succeed(), "should success starting manager")
			}()

			By("Checking that the TLS secret is created")
			isTLSSecretEventuallyPresent().Should(BeTrue(), "should eventually have the TLS secret")
			close(done)

			By("Wait a little for Reconcile to settle after mutatingwebhook configuration reconcile")
			time.Sleep(3 * time.Second)
		}, 10)
		AfterEach(func() {
			close(stopCh)
		})
		Context("and TLS secret is deleted", func() {
			BeforeEach(func() {
				By("Delete the TLS secret")
				err := cli.Delete(context.TODO(), &expectedSecret)
				Expect(err).To(Succeed(), "should succeed deleteing TLS secret")
				isTLSSecretEventuallyPresent().Should(BeFalse(), "should eventually delete the TLS secret")
			})
			It("should re-create TLS secret", func() {
				isTLSEventuallyVerified().Should(Succeed(), "should eventually have a TLS secret")
			})
		})
		Context("and CABundle is reset", func() {
			BeforeEach(func() {
				obtainedWebhookConfiguration := getWebhookConfiguration()
				obtainedWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte{}
				updateWebhookConfiguration(obtainedWebhookConfiguration)
			})
			It("should re-create CABundle", func() {
				isTLSEventuallyVerified().Should(Succeed(), "should eventually have a TLS secret")
			})
		})

	})
})

func getSecret() corev1.Secret {
	obtainedSecret := corev1.Secret{}
	err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedSecret.Namespace, Name: expectedSecret.Name}, &obtainedSecret)
	Expect(err).To(Succeed(), "should succeed getting TLS secret")
	return obtainedSecret
}

func getWebhookConfiguration() admissionregistrationv1beta1.MutatingWebhookConfiguration {
	obtainedWebhookConfiguration := admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	err := cli.Get(context.TODO(), types.NamespacedName{
		Namespace: expectedMutatingWebhookConfiguration.Namespace,
		Name:      expectedMutatingWebhookConfiguration.Name,
	}, &obtainedWebhookConfiguration)
	Expect(err).To(Succeed(), "should succeed getting mutating webhook configuration")
	return obtainedWebhookConfiguration
}

func updateWebhookConfiguration(webhookConfiguration admissionregistrationv1beta1.MutatingWebhookConfiguration) {
	err := cli.Update(context.TODO(), &webhookConfiguration)
	Expect(err).To(Succeed(), "should succeed update mutatingwebhookconfiguration")
}
