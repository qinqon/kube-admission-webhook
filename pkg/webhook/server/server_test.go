package server

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/phayes/freeport"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	certificate "github.com/qinqon/kube-admission-webhook/pkg/certificate"
)

var _ = Describe("Webhook server", func() {
	Context("when added to a controller-runtime manager and start the manager", func() {
		var (
			mgr     manager.Manager
			certDir string
			stopCh  chan struct{}
		)
		BeforeEach(func(done Done) {

			createResources()

			By("Creating new controller-runtime manager")
			var err error
			mgr, err = manager.New(testEnv.Config, manager.Options{MetricsBindAddress: "0", Namespace: expectedNamespace.Name})
			Expect(err).ToNot(HaveOccurred(), "should success creating controller-runtime manager")

			By("Creating the certDir")
			certDir, err = ioutil.TempDir("/tmp", "tls")
			Expect(err).To(Succeed(), "should success creating the cert directory")

			By("Adding new webhook server to the controller-runtime manager")
			freePort, err := freeport.GetFreePort()
			Expect(err).To(Succeed(), "should succeed selectiong a free port")

			freeportURL := strings.ReplaceAll(mutatepodURL, "8443", strconv.Itoa(freePort))
			obtainedMutatingWebhookConfiguration := admissionregistrationv1beta1.MutatingWebhookConfiguration{}

			err = cli.Get(context.TODO(), types.NamespacedName{Name: expectedMutatingWebhookConfiguration.Name}, &obtainedMutatingWebhookConfiguration)
			Expect(err).To(Succeed(), "should succeed getting mutatingwebhookconfiguration")

			obtainedMutatingWebhookConfiguration.Webhooks[0].ClientConfig.URL = &freeportURL

			err = cli.Update(context.TODO(), &obtainedMutatingWebhookConfiguration)
			Expect(err).To(Succeed(), "should succeed updating mutating webhook with freeport URL")

			mutatedPodHandler := func(ctx context.Context, req admission.Request) admission.Response {
				pod := &corev1.Pod{}

				err := json.Unmarshal(req.Object.Raw, pod)
				if err != nil {
					return admission.Errored(http.StatusBadRequest, err)
				}

				if pod.Annotations == nil {
					pod.Annotations = map[string]string{}
				}

				pod.Annotations["podmutated"] = ""

				marshaledPod, err := json.Marshal(pod)
				if err != nil {
					return admission.Errored(http.StatusInternalServerError, err)
				}

				return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
			}

			server := New(cli, certificate.Options{WebhookName: expectedMutatingWebhookConfiguration.Name, WebhookType: certificate.MutatingWebhook, Namespace: expectedNamespace.Name, CARotateInterval: certificate.OneYearDuration, CertRotateInterval: certificate.OneYearDuration},
				WithCertDir(certDir),
				WithPort(freePort),
				WithHook("/mutatepod",
					&admission.Webhook{
						Handler: admission.HandlerFunc(mutatedPodHandler),
					}),
			)

			err = server.Add(mgr)
			Expect(err).To(Succeed(), "should succeed adding the webhook server to the manager")

			By("Starting controller-runtime manager")
			stopCh = make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err = mgr.Start(stopCh)
				Expect(err).To(Succeed(), "should success starting manager")
			}()

			By("Checking that the TLS secret is created")
			obtainedSecret := corev1.Secret{}
			Eventually(func() (bool, error) {
				err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedSecret.Namespace, Name: expectedSecret.Name}, &obtainedSecret)
				if err != nil {
					if apierrors.IsNotFound(err) {
						return false, nil
					}
					return false, err
				}
				if len(obtainedSecret.Data[corev1.TLSPrivateKeyKey]) == 0 {
					return false, nil
				}
				if len(obtainedSecret.Data[corev1.TLSCertKey]) == 0 {
					return false, nil
				}
				return true, nil
			}, 5*time.Second, 1*time.Second).Should(BeTrue(), "should eventually have a TLS secret")

			By("Dump tls.key and tls.crt into webhook server certDir")
			err = ioutil.WriteFile(filepath.Join(certDir, corev1.TLSCertKey), obtainedSecret.Data[corev1.TLSCertKey], 0500)
			Expect(err).To(Succeed(), "should success dumping TLS server certificate")

			err = ioutil.WriteFile(filepath.Join(certDir, corev1.TLSPrivateKeyKey), obtainedSecret.Data[corev1.TLSPrivateKeyKey], 0500)
			Expect(err).To(Succeed(), "should success dumping TLS server key")

			close(done)
		}, 10)

		AfterEach(func() {
			close(stopCh)
			deleteResources()
			os.RemoveAll(certDir)
		})
		It("should annotate the created pod", func() {
			By("Create a pod to exercise webhook")
			Eventually(func() error {
				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: expectedNamespace.Name,
						Name:      "dummypod",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "dummy", Image: "busybox"},
						},
					},
				}
				return cli.Create(context.TODO(), &pod)
			}, 10*time.Second, 1*time.Second).Should(Succeed(), "should eventually succeed creating pod")

			By("Checking pod has being mutatated")
			obtainedPod := corev1.Pod{}
			err := cli.Get(context.TODO(), types.NamespacedName{Namespace: expectedNamespace.Name, Name: "dummypod"}, &obtainedPod)
			Expect(err).To(Succeed(), "should succeed getting the dummy pod after mutation")
			Expect(obtainedPod.Annotations).ToNot(BeEmpty(), "should annotate the created pod")
			Expect(obtainedPod.Annotations).To(HaveKeyWithValue("podmutated", ""), "should put 'podmutated' annotation into pod")
		})
	})
})
