package certificate

import (
	"context"
	"reflect"
	"testing"
	"time"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var (
	log = logf.Log.WithName("certificate/manager_test")
)

func init() {

	klog.InitFlags(nil)
	logf.SetLogger(logf.ZapLogger(true))

}

func TestReconcile(t *testing.T) {

	type TLS struct {
		caBundle, certificate, privateKey []byte
	}

	mutatingWebhookConfiguration := &admissionregistrationv1beta1.MutatingWebhookConfiguration{
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

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fooWebhook",
			Name:      "fooWebhook",
		},
	}

	objs := []runtime.Object{mutatingWebhookConfiguration, service}

	client := fake.NewFakeClient(objs...)

	getTLS := func() TLS {
		err := client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook"}, mutatingWebhookConfiguration)
		if err != nil {
			t.Fatalf("get mutatingwebhookconfiguration: (%v)", err)
		}

		clientConfig := mutatingWebhookConfiguration.Webhooks[0].ClientConfig
		if len(clientConfig.CABundle) == 0 {
			t.Fatal("CA bundle not updated")
		}

		secret := corev1.Secret{}
		err = client.Get(context.TODO(), types.NamespacedName{Name: "fooWebhook", Namespace: "fooWebhook"}, &secret)
		if err != nil {
			t.Fatalf("get secret: (%v)", err)
		}

		if secret.Type != corev1.SecretTypeTLS {
			t.Fatalf("Non TLS secret type %s", secret.Type)
		}

		if len(secret.Data) == 0 {
			t.Fatal("No tls key/cert at secret")
		}
		return TLS{
			caBundle:    clientConfig.CABundle,
			certificate: secret.Data[corev1.TLSCertKey],
			privateKey:  secret.Data[corev1.TLSPrivateKeyKey]}
	}

	certsDuration := 256 * 24 * time.Hour
	manager := NewManager(client, "fooWebhook", MutatingWebhook, certsDuration)

	// Freeze time
	now := time.Now()
	manager.now = func() time.Time { return now }

	// First call for reconcile
	firstTimeResponse, err := manager.Reconcile(reconcile.Request{})
	if err != nil {
		t.Fatalf("failed reconciling: (%v)", err)
	}
	if firstTimeResponse.RequeueAfter >= certsDuration {
		t.Fatal("Reconcile not requeued before expiration time")
	}

	firstTimeTLS := getTLS()

	// Call Reconcile in the middle of certsDuration
	manager.now = func() time.Time { return now.Add(certsDuration / 2) }
	middleTimeResponse, err := manager.Reconcile(reconcile.Request{})
	if err != nil {
		t.Fatalf("failed reconciling: (%v)", err)
	}
	if middleTimeResponse.RequeueAfter >= firstTimeResponse.RequeueAfter {
		t.Fatal("Reconcile in the middle of certificate duration not substracting 'now' from deadline")
	}

	middleTimeTLS := getTLS()

	if !reflect.DeepEqual(middleTimeTLS, firstTimeTLS) {
		t.Fatal("TLS cert/key changed on reconciling in the middle of certificate duration")
	}

	// Call Reconcile at 90% of certificates duration they should be rotated
	manager.now = func() time.Time { return now.Add(time.Duration(float64(certsDuration) * 0.9)) }
	deadlineResponse, err := manager.Reconcile(reconcile.Request{})
	if err != nil {
		t.Fatalf("failed reconciling: (%v)", err)
	}

	if deadlineResponse.RequeueAfter > firstTimeResponse.RequeueAfter {
		t.Fatal("Second Reconcile not substracting now to deadline")
	}

	deadlineTimeTLS := getTLS()
	if reflect.DeepEqual(deadlineTimeTLS, firstTimeTLS) {
		t.Fatal("TLS cert/key not changed on Reconcile after deadline")
	}

}
