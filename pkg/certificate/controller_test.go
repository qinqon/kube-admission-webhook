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
		caCertDuration          = 1 * time.Hour
		serviceCertDuration     = 30 * time.Minute
		mgr                     *Manager
		now                     time.Time
		isTLSEventuallyVerified = func() AsyncAssertion {
			return Eventually(func() error {
				return mgr.verifyTLS()
			}, 20*time.Second, 1*time.Second)
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
			}, 20*time.Second, 1*time.Second)
		}

		isCASecretEventuallyPresent = func() AsyncAssertion {
			return Eventually(func() (bool, error) {
				obtainedSecret := corev1.Secret{}
				err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedCASecret.Namespace, Name: expectedCASecret.Name}, &obtainedSecret)
				if err != nil {
					if apierrors.IsNotFound(err) {
						return false, nil
					}
					return false, err
				}
				return true, nil
			}, 20*time.Second, 1*time.Second)
		}
	)

	BeforeEach(func() {

		var err error
		mgr, err = NewManager(cli, Options{WebhookName: expectedMutatingWebhookConfiguration.Name, WebhookType: MutatingWebhook, Namespace: expectedNamespace.Name, CARotateInterval: caCertDuration, CertRotateInterval: serviceCertDuration})
		Expect(err).To(Succeed(), "should succeed constructing certificate manager")
		// Freeze time
		now = time.Now()

		createResources()
	})

	AfterEach(func() {
		deleteResources()
	})
	type TLS struct {
		caBundle, caCertificate, caPrivateKey, serviceCertificate, servicePrivateKey []byte
		caSecretAnnotations, serviceSecretAnnotations                                map[string]string
	}

	getTLS := func() TLS {
		obtainedWebhookConfiguration := admissionregistrationv1beta1.MutatingWebhookConfiguration{}
		err := cli.Get(context.TODO(), types.NamespacedName{Name: "foowebhook"}, &obtainedWebhookConfiguration)
		Expect(err).To(Succeed(), "should success getting mutatingwebhookconfiguration")

		cliConfig := obtainedWebhookConfiguration.Webhooks[0].ClientConfig
		Expect(cliConfig.CABundle).ToNot(BeEmpty(), "should update CA budle")

		obtainedCASecret := corev1.Secret{}
		err = cli.Get(context.TODO(), types.NamespacedName{Name: expectedCASecret.Name, Namespace: expectedCASecret.Namespace}, &obtainedCASecret)
		Expect(err).ToNot(HaveOccurred(), "should success getting CA secret")
		Expect(obtainedCASecret.Type).To(Equal(corev1.SecretTypeOpaque), "should be a CA secret")
		Expect(obtainedCASecret.Data).ToNot(BeEmpty(), "should contain a secret with CA key/cert")

		obtainedSecret := corev1.Secret{}
		err = cli.Get(context.TODO(), types.NamespacedName{Name: expectedSecret.Name, Namespace: expectedSecret.Namespace}, &obtainedSecret)
		Expect(err).ToNot(HaveOccurred(), "should success getting TLS secret")
		Expect(obtainedSecret.Type).To(Equal(corev1.SecretTypeTLS), "should be a TLS secret")
		Expect(obtainedSecret.Data).ToNot(BeEmpty(), "should contain a secret with TLS key/cert")

		return TLS{
			caBundle:                 cliConfig.CABundle,
			caCertificate:            obtainedCASecret.Data[CACertKey],
			caPrivateKey:             obtainedCASecret.Data[CAPrivateKeyKey],
			caSecretAnnotations:      obtainedCASecret.Annotations,
			serviceCertificate:       obtainedSecret.Data[corev1.TLSCertKey],
			servicePrivateKey:        obtainedSecret.Data[corev1.TLSPrivateKeyKey],
			serviceSecretAnnotations: obtainedSecret.Annotations,
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
			By("Reconcile for the first time")
			currentResult, err = mgr.Reconcile(reconcile.Request{})
			Expect(err).To(Succeed(), "should success reconciling")
			currentTLS = getTLS()
		})

		It("should create TLS cert/key with proper annotation and return proper deadline", func() {
			Expect(currentTLS.caSecretAnnotations).To(HaveKey(secretManagedAnnotatoinKey), "should be marked as managed by the kube-admission-webhook cert-manager")
			Expect(currentTLS.serviceSecretAnnotations).To(HaveKey(secretManagedAnnotatoinKey), "should be marked as managed by the kube-admission-webhook cert-manager")
			Expect(currentResult.RequeueAfter).To(BeNumerically(">", time.Duration(0)), "should not be zero")
			Expect(currentResult.RequeueAfter).To(Equal(mgr.elapsedToRotateServicesFromLastDeadline()), "should schedule new Reconcile after first Reconcile to rotate service cert")
		})
		Context("and then called in the middle of service cert deadline", func() {
			BeforeEach(func() {
				previousTLS = currentTLS
				previousResult = currentResult
				now = mgr.now().Add(serviceCertDuration / 2)
				mgr.now = func() time.Time { return now }
				triple.Now = mgr.now
				var err error
				By("Reconcile in the middle of service cert deadline")
				currentResult, err = mgr.Reconcile(reconcile.Request{})
				Expect(err).To(Succeed(), "should success reconciling")

				currentTLS = getTLS()
			})
			It("should not rotate service cert and return a reduced deadline", func() {
				Expect(currentResult.RequeueAfter).To(BeNumerically("<", previousResult.RequeueAfter), "should subsctract 'now' from service cert deadline at reconcile in the middle of service certificate duration")
				Expect(currentResult.RequeueAfter).To(Equal(mgr.elapsedToRotateServicesFromLastDeadline()), "should schedule new Reconcile rotate service cert")
				Expect(currentTLS).To(Equal(previousTLS), "should not change TLS cert/key on reconcile in the middle of certificate duration")
			})

			Context("and called at previous RequeueAfter (service cert rotation deadline)", func() {
				BeforeEach(func() {
					previousTLS = currentTLS
					previousResult = currentResult
					// Emulate controller-runtime timer by adding previous RequeueAfter values to previousNow
					now = mgr.now().Add(previousResult.RequeueAfter)
					mgr.now = func() time.Time { return now }
					triple.Now = mgr.now
					var err error
					By("Reconcile at service cert rotation deadline")
					currentResult, err = mgr.Reconcile(reconcile.Request{})
					Expect(err).To(Succeed(), "should success reconciling")
					currentTLS = getTLS()
				})
				It("should rotate service cert/key and return a new deadline", func() {
					Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
					Expect(currentTLS.servicePrivateKey).ToNot(Equal(previousTLS.servicePrivateKey), "should have do a TLS key rotation")
					Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
					Expect(currentTLS.caBundle).To(Equal(previousTLS.caBundle), "shouldn't have rotate CABundle ")
					Expect(currentTLS.caCertificate).To(Equal(previousTLS.caCertificate), "shouldn't have rotate CA certificate")
					Expect(currentTLS.caPrivateKey).To(Equal(previousTLS.caPrivateKey), "shouldn't have rotate CA key rotation")
					Expect(currentTLS.caSecretAnnotations).To(Equal(previousTLS.caSecretAnnotations), "should containe same secret annotations")
					Expect(currentResult.RequeueAfter).To(Equal(mgr.elapsedToRotateServicesFromLastDeadline()), "should schedule new Reconcile after service cert rotation to rotate service cert again")
				})
				Context("and called at previous RequeueAfter (second service cert rotation deadline)", func() {
					BeforeEach(func() {
						previousTLS = currentTLS
						previousResult = currentResult
						// Emulate controller-runtime timer by adding previous RequeueAfter values to previousNow
						now = mgr.now().Add(previousResult.RequeueAfter)
						mgr.now = func() time.Time { return now }
						triple.Now = mgr.now
						var err error
						By("Reconcile at second service cert rotation deadline")
						currentResult, err = mgr.Reconcile(reconcile.Request{})
						Expect(err).To(Succeed(), "should success reconciling")
						currentTLS = getTLS()
					})
					It("should rotate service cert/key and return a new deadline", func() {
						Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
						Expect(currentTLS.servicePrivateKey).ToNot(Equal(previousTLS.servicePrivateKey), "should have do a TLS key rotation")
						Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
						Expect(currentTLS.caBundle).To(Equal(previousTLS.caBundle), "shouldn't have rotate CABundle ")
						Expect(currentTLS.caCertificate).To(Equal(previousTLS.caCertificate), "shouldn't have rotate CA certificate")
						Expect(currentTLS.caPrivateKey).To(Equal(previousTLS.caPrivateKey), "shouldn't have rotate CA key rotation")
						Expect(currentTLS.caSecretAnnotations).To(Equal(previousTLS.caSecretAnnotations), "should containe same secret annotations")
						Expect(currentResult.RequeueAfter).To(Equal(mgr.elapsedToRotateCAFromLastDeadline()), "should schedule new Reconcile after service cert rotation to rotate service cert again")
					})
					Context("and called at previous RequeueAfter (ca cert rotation deadline)", func() {
						BeforeEach(func() {
							previousTLS = currentTLS
							previousResult = currentResult
							// Emulate controller-runtime timer by adding previous RequeueAfter values to previousNow
							now = mgr.now().Add(previousResult.RequeueAfter)
							mgr.now = func() time.Time { return now }
							triple.Now = mgr.now
							var err error
							By("Reconcile at ca cert rotation deadline")
							currentResult, err = mgr.Reconcile(reconcile.Request{})
							Expect(err).To(Succeed(), "should success reconciling")
							currentTLS = getTLS()
						})
						It("should rotate CA and service certs and return new deadline", func() {
							Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
							Expect(currentTLS.servicePrivateKey).ToNot(Equal(previousTLS.servicePrivateKey), "should have do a TLS key rotation")
							Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
							Expect(currentTLS.caBundle).ToNot(Equal(previousTLS.caBundle), "should have rotate CABundle ")
							Expect(currentTLS.caCertificate).ToNot(Equal(previousTLS.caCertificate), "should have rotate CA certificate")
							Expect(currentTLS.caPrivateKey).ToNot(Equal(previousTLS.caPrivateKey), "should have rotate CA key rotation")

							elapsedForCleanup, err := mgr.earliestElapsedForCleanup()
							Expect(err).To(Succeed(), "should succeed calculating earliestElapsedForCleanup")
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
								By("Reconcile at cleanup deadline")
								currentResult, err = mgr.Reconcile(reconcile.Request{})
								Expect(err).To(Succeed(), "should success reconciling")
								currentTLS = getTLS()
							})
							It("should remove expired CA certificates from caBundle", func() {
								Expect(currentTLS.caBundle).ToNot(Equal(previousTLS.caBundle), "should have do a caBundle cleanup")
								Expect(currentTLS.serviceCertificate).To(Equal(previousTLS.serviceCertificate), "should containe same TLS cert")
								Expect(currentTLS.servicePrivateKey).To(Equal(previousTLS.servicePrivateKey), "should containe same TLS key")
								Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
								Expect(currentTLS.caCertificate).To(Equal(previousTLS.caCertificate), "shouldn't have rotate CA certificate")
								Expect(currentTLS.caPrivateKey).To(Equal(previousTLS.caPrivateKey), "shouldn't have rotate CA key rotation")

								cas, err := triple.ParseCertsPEM(currentTLS.caBundle)
								Expect(err).To(Succeed(), "should succeed parssing caBundle")
								Expect(cas).To(HaveLen(1), "should have cleandup CA bundle with expired certificates gone")

								Expect(currentResult.RequeueAfter).To(Equal(mgr.elapsedToRotateServicesFromLastDeadline()), "should schedule new Reconcile after ca overlapping cleanup to rotate service cert")
							})
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
				crManager, err = manager.New(testEnv.Config, manager.Options{MetricsBindAddress: "0"})
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
			Context("and CA secret is deleted", func() {
				BeforeEach(func() {
					By("Delete the CA secret")
					err := cli.Delete(context.TODO(), &expectedCASecret)
					Expect(err).To(Succeed(), "should succeed deleteing CA secret")
					By("Checking that the CA secret is deleted")
					isCASecretEventuallyPresent().Should(BeFalse(), "should eventually delete the CA secret")
				})
				It("should re-create CA secret", func() {
					isTLSEventuallyVerified().Should(Succeed(), "should eventually have a CA secret")
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
