package certificate

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var _ = Describe("certificate manager", func() {
	type setRotationDeadlineCase struct {
		notBefore    time.Duration
		notAfter     time.Duration
		shouldRotate bool
	}
	DescribeTable("SetRotationDeadline",
		func(c setRotationDeadlineCase) {
			log := logf.Log.WithName("webhook/server/certificate/manager_test")
			now := time.Now()
			notAfter := now.Add(c.notAfter)
			notBefore := now.Add(c.notBefore)
			defer func(original func(float64) time.Duration) { jitteryDuration = original }(jitteryDuration)
			m := Manager{
				caCert: &x509.Certificate{
					NotBefore: notBefore,
					NotAfter:  notAfter,
				},
				now: func() time.Time { return now },
				log: log,
			}
			jitteryDuration = func(float64) time.Duration { return time.Duration(float64(notAfter.Sub(notBefore)) * 0.7) }
			lowerBound := notBefore.Add(time.Duration(float64(notAfter.Sub(notBefore)) * 0.7))

			deadline := m.nextRotationDeadline()

			Expect(deadline).To(Equal(lowerBound), fmt.Sprintf("should match deadline for notBefore %v and notAfter %v", notBefore, notAfter))

		},
		Entry("just issued, still good", setRotationDeadlineCase{
			notBefore:    -1 * time.Hour,
			notAfter:     99 * time.Hour,
			shouldRotate: false,
		}),
		Entry("half way expired, still good", setRotationDeadlineCase{
			notBefore:    -24 * time.Hour,
			notAfter:     24 * time.Hour,
			shouldRotate: false,
		}),
		Entry("mostly expired, still good", setRotationDeadlineCase{
			notBefore:    -69 * time.Hour,
			notAfter:     31 * time.Hour,
			shouldRotate: false,
		}),
		Entry("just about expired, should rotate", setRotationDeadlineCase{
			notBefore:    -91 * time.Hour,
			notAfter:     9 * time.Hour,
			shouldRotate: true,
		}),
		Entry("nearly expired, should rotate", setRotationDeadlineCase{
			notBefore:    -99 * time.Hour,
			notAfter:     1 * time.Hour,
			shouldRotate: true,
		}),
		Entry("already expired, should rotate", setRotationDeadlineCase{
			notBefore:    -10 * time.Hour,
			notAfter:     -1 * time.Hour,
			shouldRotate: true,
		}),
		Entry("long duration", setRotationDeadlineCase{
			notBefore:    -6 * 30 * 24 * time.Hour,
			notAfter:     6 * 30 * 24 * time.Hour,
			shouldRotate: true,
		}),
		Entry("short duration", setRotationDeadlineCase{
			notBefore:    -30 * time.Second,
			notAfter:     30 * time.Second,
			shouldRotate: true,
		}),
	)
	Context("when waitForDeadlineAndRotate is called for the first time", func() {
		var (
			certsDuration                = 30 * time.Second
			manager                      *Manager
			client                       client.Client
			mutatingWebhookConfiguration = &admissionregistrationv1beta1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fooWebhook",
				},
				Webhooks: []admissionregistrationv1beta1.MutatingWebhook{
					admissionregistrationv1beta1.MutatingWebhook{
						Name: "fooWebhook",
						ClientConfig: admissionregistrationv1beta1.WebhookClientConfig{
							Service: &admissionregistrationv1beta1.ServiceReference{
								Name:      "fooWebhook",
								Namespace: "fooWebhook",
							},
						},
					},
				},
			}

			service = &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fooWebhook",
					Name:      "fooWebhook",
				},
			}
		)
		BeforeEach(func() {
			By("Init fake client with mutatingwebhookconfiguration and service")
			objs := []runtime.Object{mutatingWebhookConfiguration, service}
			client = fake.NewFakeClient(objs...)

			By("Calling waitForDeadlineAndRotate for the first time")
			manager = NewManager(client, "fooWebhook", MutatingWebhook, certsDuration)
			manager.waitForDeadlineAndRotate()
			//TODO Implement ErrorsHandler to take the errors that we have at
			//     background

		})
		It("should create the secret and rotate CA and server certificates", func() {

			err := client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook"}, mutatingWebhookConfiguration)
			Expect(err).ToNot(HaveOccurred(), "should success getting mutatingwebhookconfiguration")

			clientConfig := mutatingWebhookConfiguration.Webhooks[0].ClientConfig
			Expect(clientConfig.CABundle).ToNot(BeEmpty(), "should update CA budle")

			secret := corev1.Secret{}
			err = client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook", Namespace: "fooWebhook"}, &secret)
			Expect(err).ToNot(HaveOccurred(), "should success getting secret")
			Expect(secret.Type).To(Equal(corev1.SecretTypeTLS), "should be a TLS secret")
			Expect(secret.Data).ToNot(BeEmpty(), "should contain a secret with TLS key/cert")
		})
		Context("and called a second time", func() {
			var (
				secret       corev1.Secret
				start        time.Time
				clientConfig admissionregistrationv1beta1.WebhookClientConfig
			)
			BeforeEach(func() {
				err := client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook"}, mutatingWebhookConfiguration)
				Expect(err).ToNot(HaveOccurred(), "should success getting mutatingwebhookconfiguration")
				clientConfig = mutatingWebhookConfiguration.Webhooks[0].ClientConfig

				err = client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook", Namespace: "fooWebhook"}, &secret)
				Expect(err).ToNot(HaveOccurred(), "should success getting secret")

				start = time.Now()
				By("Calling waitForDeadlineAndRotate for the second time")
				manager.waitForDeadlineAndRotate()
			})

			It("should wait until expiration deadline and rotate secret and caBundle", func() {
				elapsed := time.Now().Sub(start)
				Expect(elapsed).To(SatisfyAll(BeNumerically(">=", float64(certsDuration)*0.8), BeNumerically("<=", float64(certsDuration)*0.9)), "should wait the jittered elapsed time ")

				err := client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook"}, mutatingWebhookConfiguration)
				Expect(err).ToNot(HaveOccurred(), "should success getting mutatingwebhookconfiguration")

				newClientConfig := mutatingWebhookConfiguration.Webhooks[0].ClientConfig
				Expect(newClientConfig.CABundle).ToNot(Equal(clientConfig.CABundle), "should rotate CA bundle")

				newSecret := corev1.Secret{}
				err = client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook", Namespace: "fooWebhook"}, &newSecret)
				Expect(err).ToNot(HaveOccurred(), "should success getting secret")
				Expect(newSecret.Data[corev1.TLSPrivateKeyKey]).ToNot(Equal(secret.Data[corev1.TLSPrivateKeyKey]), "should rotate TLS server key")
				Expect(newSecret.Data[corev1.TLSCertKey]).ToNot(Equal(secret.Data[corev1.TLSCertKey]), "should rotate TLS server certificate")
			})
		})
	})
})
