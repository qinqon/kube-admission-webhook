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
			}, 20*time.Second, 1*time.Second)
		}
		isTLSSecretPresent = func() (bool, error) {
			obtainedSecret := corev1.Secret{}
			err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedSecret.Namespace, Name: expectedSecret.Name}, &obtainedSecret)
			if err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return false, err
			}
			return true, nil
		}
		isTLSSecretEventuallyPresent = func() AsyncAssertion {
			return Eventually(isTLSSecretPresent, 20*time.Second, 1*time.Second)
		}
		isTLSSecretConsistentlyPresent = func() AsyncAssertion {
			return Consistently(isTLSSecretPresent, 5*time.Second, 1*time.Second)
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
		secretAnnotations                 map[string]string
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
			caBundle:          cliConfig.CABundle,
			certificate:       obtainedSecret.Data[corev1.TLSCertKey],
			privateKey:        obtainedSecret.Data[corev1.TLSPrivateKeyKey],
			secretAnnotations: obtainedSecret.Annotations,
		}
	}
	Context("when reconcile is called for the first time", func() {
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
			currentTLS = getTLS()
		})

		It("should create TLS cert/key with proper annotation and return proper deadline", func() {
			Expect(currentTLS.secretAnnotations).To(HaveKey(secretManagedAnnotatoinKey), "should be marked as managed by the kube-admission-webhook cert-manager")
			Expect(currentResult.RequeueAfter).To(BeNumerically("<", certsDuration), "should requeue before expiration time")
		})
		Context("and then called in the middle of the deadline", func() {
			BeforeEach(func() {
				previousTLS = currentTLS
				previousResult = currentResult
				now = mgr.now().Add(certsDuration / 2)
				mgr.now = func() time.Time { return now }
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

			Context("and called at previous RequeueAfter (rotation deadline)", func() {
				BeforeEach(func() {
					previousTLS = currentTLS
					previousResult = currentResult
					// Emulate controller-runtime timer by adding previous RequeueAfter values to previousNow
					now = mgr.now().Add(previousResult.RequeueAfter)
					mgr.now = func() time.Time { return now }
					triple.Now = mgr.now
					var err error
					currentResult, err = mgr.Reconcile(reconcile.Request{})
					Expect(err).To(Succeed(), "should success reconciling")
					currentTLS = getTLS()
				})
				It("should rotate TLS cert/key and return a new deadline", func() {
					Expect(currentTLS.caBundle).ToNot(Equal(previousTLS.caBundle), "should have do a CA rotation")
					Expect(currentTLS.certificate).ToNot(Equal(previousTLS.certificate), "should have do TLS cert rotation")
					Expect(currentTLS.privateKey).ToNot(Equal(previousTLS.privateKey), "should have do a TLS key rotation")
					Expect(currentTLS.secretAnnotations).To(Equal(previousTLS.secretAnnotations), "should containe same secret annotations")
					elapsedForCleanup, err := mgr.earliestElapsedForCleanup()
					Expect(err).To(Succeed(), "should succeed caslculating earliestElapsedForCleanup")
					Expect(currentResult.RequeueAfter).To(Equal(elapsedForCleanup), "Reconcile at rotate should schedule next Reconcile to do the CA overlapping cleanup")

					cas, err := triple.ParseCertsPEM(currentTLS.caBundle)
					Expect(err).To(Succeed(), "should succeed parssing caBundle")
					Expect(cas).To(HaveLen(2), "should overlap CAs")
				})
				Context("and called again at previous RequeueAfter (cleanup deadline)", func() {
					BeforeEach(func() {
						previousTLS = currentTLS
						previousResult = currentResult
						now = mgr.now().Add(previousResult.RequeueAfter)
						mgr.now = func() time.Time { return now }
						triple.Now = mgr.now
						var err error
						currentResult, err = mgr.Reconcile(reconcile.Request{})
						Expect(err).To(Succeed(), "should success reconciling")
						currentTLS = getTLS()
					})
					It("should remove expired CA certificates from caBundle", func() {
						Expect(currentTLS.caBundle).ToNot(Equal(previousTLS.caBundle), "should have do a caBundle cleanup")
						Expect(currentTLS.certificate).To(Equal(previousTLS.certificate), "should containe same TLS cert")
						Expect(currentTLS.privateKey).To(Equal(previousTLS.privateKey), "should containe same TLS key")
						Expect(currentTLS.secretAnnotations).To(Equal(previousTLS.secretAnnotations), "should containe same secret annotations")

						cas, err := triple.ParseCertsPEM(currentTLS.caBundle)
						Expect(err).To(Succeed(), "should succeed parssing caBundle")
						Expect(cas).To(HaveLen(1), "should have cleandup CA bundle with expired certificates gone")

						Expect(currentResult.RequeueAfter).To(Equal(mgr.elapsedToRotateFromLastDeadline()), "should schedule new Reconcile after ca overlapping cleanup to rotate current ca cert")
					})
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
				By("Checking that the TLS secret is deleted")
				isTLSSecretEventuallyPresent().Should(BeFalse(), "should eventually delete the TLS secret")
			})
			It("should re-create TLS secret", func() {
				isTLSEventuallyVerified().Should(Succeed(), "should eventually have a TLS secret")
			})
		})
		Context("and TLS secret is deleted using cascade deletion", func() {
			BeforeEach(func() {
				// Emulate cascade deletion by breaking ownership and
				// setting it to a non existing one
				By("Break TLS secret ownership")
				obtainedSecret := corev1.Secret{}
				err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedSecret.Namespace, Name: expectedSecret.Name}, &obtainedSecret)
				Expect(err).To(Succeed(), "should succeed getting the secret")
				obtainedSecret.OwnerReferences[0].Name = "bad-service"
				err = cli.Update(context.TODO(), &obtainedSecret)
				Expect(err).To(Succeed(), "should succeed updating the TLS secret")

				By("Wait a little for Reconcile to settle after updating secret")
				time.Sleep(3 * time.Second)

				By("Delete the TLS secret")
				err = cli.Delete(context.TODO(), &obtainedSecret)
				Expect(err).To(Succeed(), "should succeed deleting TLS secret")
				isTLSSecretEventuallyPresent().Should(BeFalse(), "should eventually delete the TLS secret")
			})
			It("should not re-create the TLS secret", func() {
				isTLSSecretConsistentlyPresent().Should(BeFalse(), "should not re-create the TLS secret")
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
