package certificate

import (
	"context"
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/chain"
	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

var (
	log = logf.Log.WithName("certificate/manager_test")
)

var _ = Describe("Certificates controller", func() {
	var (
		caCertDuration          = 70 * time.Minute
		caOverlapDuration       = caCertDuration / 10
		serviceCertDuration     = 30 * time.Minute
		serviceOverlapDuration  = serviceCertDuration / 10
		mgr                     *Manager
		now                     time.Time
		t0                      time.Time
		isTLSEventuallyVerified = func() AsyncAssertion {
			return Eventually(func() error {
				secret, err := getSecret()
				if err != nil {
					return err
				}
				if secret.Data == nil {
					return errors.New("Service secret has no Data")
				}
				key, ok := secret.Data[corev1.TLSPrivateKeyKey]
				if !ok {
					return errors.New("Service secret has no key")
				}
				cert, ok := secret.Data[corev1.TLSCertKey]
				if !ok {
					return errors.New("Service secret has no cert")
				}

				webhook := getWebhookConfiguration()

				return triple.VerifyTLS(cert, key, webhook.Webhooks[0].ClientConfig.CABundle)
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
		mgr, err = NewManager(
			expectedMutatingWebhookConfiguration.Name,
			expectedNamespace.Name,
			cli,
			chain.Options{
				CARotateInterval:    caCertDuration,
				CAOverlapInterval:   caOverlapDuration,
				CertRotateInterval:  serviceCertDuration,
				CertOverlapInterval: serviceOverlapDuration,
			},
			[]WebhookReference{
				{
					Type: MutatingWebhook,
					Name: expectedMutatingWebhookConfiguration.Name,
				},
			},
		)
		Expect(err).To(Succeed(), "should succeed constructing certificate manager")
		// Freeze time, to the most recent second in UTC for easier reading
		now = time.Now().Truncate(time.Second).UTC()
		t0 = now

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
		obtainedWebhookConfiguration := getWebhookConfiguration()

		cliConfig := obtainedWebhookConfiguration.Webhooks[0].ClientConfig
		Expect(cliConfig.CABundle).ToNot(BeEmpty(), "should update CA budle")

		obtainedCASecret, err := getCASecret()
		Expect(err).ToNot(HaveOccurred(), "should success getting CA secret")
		Expect(obtainedCASecret.Type).To(Equal(corev1.SecretTypeOpaque), "should be a CA secret")
		Expect(obtainedCASecret.Data).ToNot(BeEmpty(), "should contain a secret with CA key/cert")

		obtainedSecret, err := getSecret()
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
			currentResult           reconcile.Result
			previousTLS, currentTLS TLS
			backToTheFuture         = func(step string, future time.Duration) {
				previousTLS = currentTLS
				now = now.Add(future)
				triple.Now = func() time.Time { return now }
				var err error
				By(fmt.Sprintf("%s t: %s", step, future))
				currentResult, err = mgr.Reconcile(context.Background(), reconcile.Request{})
				Expect(err).To(Succeed(), "should success reconciling")
				currentTLS = getTLS()
			}
		)
		BeforeEach(func() {
			backToTheFuture("Reconcile for the first time", 0)
		})

		It("should create TLS cert/key with proper annotation and return proper deadline", func() {
			Expect(currentTLS.caSecretAnnotations).To(HaveKey(secretManagedAnnotationKey), "should be marked as managed by the kube-admission-webhook cert-manager")
			Expect(currentTLS.serviceSecretAnnotations).To(HaveKey(secretManagedAnnotationKey), "should be marked as managed by the kube-admission-webhook cert-manager")
			durationToFirstRotation := t0.Add(serviceCertDuration - serviceOverlapDuration).Sub(now)
			Expect(currentResult.RequeueAfter).To(Equal(durationToFirstRotation), "should schedule new Reconcile after first Reconcile to rotate service cert")
		})
		Context("and then called in the middle of service cert deadline", func() {
			BeforeEach(func() {
				backToTheFuture("Reconcile in the middle of service cert deadline", serviceCertDuration/2)
			})
			It("should not rotate service cert and return a reduced deadline", func() {
				durationToFirstRotation := t0.Add(serviceCertDuration - serviceOverlapDuration).Sub(now)
				Expect(currentResult.RequeueAfter).To(Equal(durationToFirstRotation), "should schedule new Reconcile rotate service cert")
				Expect(currentTLS).To(Equal(previousTLS), "should not change TLS cert/key on reconcile in the middle of certificate duration")
			})

			Context("and called at previous RequeueAfter (service cert rotation deadline)", func() {
				BeforeEach(func() {
					backToTheFuture("Reconcile at service cert rotation deadline", currentResult.RequeueAfter)
				})
				It("should rotate service cert/key and return a new deadline", func() {
					Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
					Expect(currentTLS.servicePrivateKey).ToNot(Equal(previousTLS.servicePrivateKey), "should have do a TLS key rotation")
					Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
					Expect(currentTLS.caBundle).To(Equal(previousTLS.caBundle), "shouldn't have rotate CABundle ")
					Expect(currentTLS.caCertificate).To(Equal(previousTLS.caCertificate), "shouldn't have rotate CA certificate")
					Expect(currentTLS.caPrivateKey).To(Equal(previousTLS.caPrivateKey), "shouldn't have rotate CA key rotation")
					Expect(currentTLS.caSecretAnnotations).To(Equal(previousTLS.caSecretAnnotations), "should containe same secret annotations")
					durationToFirstCleanup := t0.Add(serviceCertDuration).Sub(now)
					Expect(currentResult.RequeueAfter).To(Equal(durationToFirstCleanup), "should schedule new Reconcile after service cert rotation to cleanup overlap")

					certs, err := triple.ParseCertsPEM(currentTLS.serviceCertificate)
					Expect(err).To(Succeed(), "should succeed parsing service certificates")
					Expect(certs).To(HaveLen(2), "should overlap service certs")
				})
				Context("and called at previous RequeueAfter (service certificate overlap cleanup)", func() {
					BeforeEach(func() {
						backToTheFuture("Reconcile at service certificate overlap cleanup", currentResult.RequeueAfter)
					})
					It("should cleanup service cert, keeping service key and return a new deadline", func() {
						Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
						Expect(currentTLS.servicePrivateKey).To(Equal(previousTLS.servicePrivateKey), "should have not do a TLS key rotation")
						Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
						Expect(currentTLS.caBundle).To(Equal(previousTLS.caBundle), "shouldn't have rotate CABundle ")
						Expect(currentTLS.caCertificate).To(Equal(previousTLS.caCertificate), "shouldn't have rotate CA certificate")
						Expect(currentTLS.caPrivateKey).To(Equal(previousTLS.caPrivateKey), "shouldn't have rotate CA key rotation")
						Expect(currentTLS.caSecretAnnotations).To(Equal(previousTLS.caSecretAnnotations), "should containe same secret annotations")
						durationToSecondRotation := t0.Add(2 * (serviceCertDuration - serviceOverlapDuration)).Sub(now)
						Expect(currentResult.RequeueAfter).To(Equal(durationToSecondRotation), "should schedule new Reconcile after service cert rotation to rotate service cert again")

						certs, err := triple.ParseCertsPEM(currentTLS.serviceCertificate)
						Expect(err).To(Succeed(), "should succeed parsing service certificates")
						Expect(certs).To(HaveLen(1), "should have cleanup overlap service certs")
					})

					Context("and called at previous RequeueAfter (second service cert rotation deadline)", func() {
						BeforeEach(func() {
							backToTheFuture("Reconcile at second service cert rotation deadline", currentResult.RequeueAfter)
						})
						It("should rotate service cert/key and return a new deadline", func() {
							Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
							Expect(currentTLS.servicePrivateKey).ToNot(Equal(previousTLS.servicePrivateKey), "should have do a TLS key rotation")
							Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
							Expect(currentTLS.caBundle).To(Equal(previousTLS.caBundle), "shouldn't have rotate CABundle ")
							Expect(currentTLS.caCertificate).To(Equal(previousTLS.caCertificate), "shouldn't have rotate CA certificate")
							Expect(currentTLS.caPrivateKey).To(Equal(previousTLS.caPrivateKey), "shouldn't have rotate CA key rotation")
							Expect(currentTLS.caSecretAnnotations).To(Equal(previousTLS.caSecretAnnotations), "should containe same secret annotations")
							durationToSecondCleanup := t0.Add(2*serviceCertDuration - serviceOverlapDuration).Sub(now)
							Expect(currentResult.RequeueAfter).To(Equal(durationToSecondCleanup), "should schedule new Reconcile after service cert rotation to cleanup overlap")

							certs, err := triple.ParseCertsPEM(currentTLS.serviceCertificate)
							Expect(err).To(Succeed(), "should succeed parsing service certificates")
							Expect(certs).To(HaveLen(2), "should have service cert overlap")
						})
						Context("and called at previous RequeueAfter (second service certificate overlap cleanup)", func() {
							BeforeEach(func() {
								backToTheFuture("Reconcile at second service certificate overlap cleanup", currentResult.RequeueAfter)
							})
							It("should rotate service cert/key and return a new deadline", func() {
								Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
								Expect(currentTLS.servicePrivateKey).To(Equal(previousTLS.servicePrivateKey), "should have do a TLS key rotation")
								Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
								Expect(currentTLS.caBundle).To(Equal(previousTLS.caBundle), "shouldn't have rotate CABundle ")
								Expect(currentTLS.caCertificate).To(Equal(previousTLS.caCertificate), "shouldn't have rotate CA certificate")
								Expect(currentTLS.caPrivateKey).To(Equal(previousTLS.caPrivateKey), "shouldn't have rotate CA key rotation")
								Expect(currentTLS.caSecretAnnotations).To(Equal(previousTLS.caSecretAnnotations), "should containe same secret annotations")
								durationToFirstCARotation := t0.Add(caCertDuration - caOverlapDuration).Sub(now)
								Expect(currentResult.RequeueAfter).To(Equal(durationToFirstCARotation), "should schedule new Reconcile after service cert rotation to rotate CA cert")

								certs, err := triple.ParseCertsPEM(currentTLS.serviceCertificate)
								Expect(err).To(Succeed(), "should succeed parsing service certificates")
								Expect(certs).To(HaveLen(1), "should have cleanup overlap service certs")
							})
							Context("and called at previous RequeueAfter (ca cert rotation deadline)", func() {
								BeforeEach(func() {
									backToTheFuture("Reconcile at ca cert rotation deadline", currentResult.RequeueAfter)
								})
								It("should rotate CA and service certs and return new deadline", func() {
									Expect(currentTLS.serviceCertificate).ToNot(Equal(previousTLS.serviceCertificate), "should have do TLS cert rotation")
									Expect(currentTLS.servicePrivateKey).ToNot(Equal(previousTLS.servicePrivateKey), "should have do a TLS key rotation")
									Expect(currentTLS.serviceSecretAnnotations).To(Equal(previousTLS.serviceSecretAnnotations), "should containe same secret annotations")
									Expect(currentTLS.caBundle).ToNot(Equal(previousTLS.caBundle), "should have rotate CABundle ")
									Expect(currentTLS.caCertificate).ToNot(Equal(previousTLS.caCertificate), "should have rotate CA certificate")
									Expect(currentTLS.caPrivateKey).ToNot(Equal(previousTLS.caPrivateKey), "should have rotate CA key rotation")
									durationToFirstCACleanup := t0.Add(caCertDuration).Sub(now)
									Expect(currentResult.RequeueAfter).To(Equal(durationToFirstCACleanup), "Reconcile at rotate should schedule next Reconcile to do the CA overlapping cleanup")

									cas, err := triple.ParseCertsPEM(currentTLS.caBundle)
									Expect(err).To(Succeed(), "should succeed parssing caBundle")
									Expect(cas).To(HaveLen(2), "should overlap CAs")
								})
								Context("and called again at previous RequeueAfter (ca cleanup deadline)", func() {
									BeforeEach(func() {
										backToTheFuture("Reconcile at ca cleanup deadline", currentResult.RequeueAfter)
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
										durationToThirdRotation := t0.Add(caCertDuration - caOverlapDuration + serviceCertDuration - serviceOverlapDuration).Sub(now)
										Expect(currentResult.RequeueAfter).To(Equal(durationToThirdRotation), "should schedule new Reconcile after CA cleanup to rotate service cert")
									})
								})
							})
						})
					})
				})

			})
		})
	})
	Context("when integrated into a controller-runtime manager and started", func() {
		var (
			crManager manager.Manager
			cancel    context.CancelFunc
		)
		BeforeEach(func(done Done) {

			By("Creating new controller-runtime manager")
			var err error
			crManager, err = manager.New(testEnv.Config, manager.Options{MetricsBindAddress: "0"})
			Expect(err).ToNot(HaveOccurred(), "should success creating controller-runtime manager")

			err = mgr.Add(crManager)
			Expect(err).To(Succeed(), "should succeed adding the cert manager controller to the controller-runtime manager")

			By("Starting controller-runtime manager")
			var ctx context.Context
			ctx, cancel = context.WithCancel(context.Background())
			go func() {
				defer GinkgoRecover()
				err = crManager.Start(ctx)
				Expect(err).To(Succeed(), "should success starting manager")
			}()

			By("Checking that the TLS secret is created")
			isTLSSecretEventuallyPresent().Should(BeTrue(), "should eventually have the TLS secret")
			close(done)

			By("Wait a little for Reconcile to settle after mutatingwebhook configuration reconcile")
			time.Sleep(3 * time.Second)
		}, 10)
		AfterEach(func() {
			defer cancel()
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
				By("Removing CABundle field")
				updateWebhookConfiguration(obtainedWebhookConfiguration)
			})
			It("should re-create CABundle", func() {
				isTLSEventuallyVerified().Should(Succeed(), "should eventually have a TLS secret")
			})
		})
	})
})

func getCASecret() (corev1.Secret, error) {
	obtainedSecret := corev1.Secret{}
	err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedCASecret.Namespace, Name: expectedCASecret.Name}, &obtainedSecret)
	return obtainedSecret, err
}

func getSecret() (corev1.Secret, error) {
	obtainedSecret := corev1.Secret{}
	err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedSecret.Namespace, Name: expectedSecret.Name}, &obtainedSecret)
	return obtainedSecret, err
}

func getWebhookConfiguration() admissionregistrationv1.MutatingWebhookConfiguration {
	obtainedWebhookConfiguration := admissionregistrationv1.MutatingWebhookConfiguration{}
	err := cli.Get(context.TODO(), types.NamespacedName{
		Namespace: expectedMutatingWebhookConfiguration.Namespace,
		Name:      expectedMutatingWebhookConfiguration.Name,
	}, &obtainedWebhookConfiguration)
	Expect(err).To(Succeed(), "should succeed getting mutating webhook configuration")
	return obtainedWebhookConfiguration
}

func updateWebhookConfiguration(webhookConfiguration admissionregistrationv1.MutatingWebhookConfiguration) {
	err := cli.Update(context.TODO(), &webhookConfiguration)
	Expect(err).To(Succeed(), "should succeed update mutatingwebhookconfiguration")
}
