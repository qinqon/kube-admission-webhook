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
	var (
		certsDuration = 256 * 24 * time.Hour
		mgr           *Manager
		now           time.Time
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
})
