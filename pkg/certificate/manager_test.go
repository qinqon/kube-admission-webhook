package certificate

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNextRotateDeadlineForCert(t *testing.T) {

	defer func(original func(float64) time.Duration) { jitteryDuration = original }(jitteryDuration)

	now := time.Now()

	testCases := []struct {
		name         string
		notBefore    time.Time
		notAfter     time.Time
		shouldRotate bool
	}{
		{"just issued, still good", now.Add(-1 * time.Hour), now.Add(99 * time.Hour), false},
		{"half way expired, still good", now.Add(-24 * time.Hour), now.Add(24 * time.Hour), false},
		{"mostly expired, still good", now.Add(-69 * time.Hour), now.Add(31 * time.Hour), false},
		{"just about expired, should rotate", now.Add(-91 * time.Hour), now.Add(9 * time.Hour), true},
		{"nearly expired, should rotate", now.Add(-99 * time.Hour), now.Add(1 * time.Hour), true},
		{"already expired, should rotate", now.Add(-10 * time.Hour), now.Add(-1 * time.Hour), true},
		{"long duration", now.Add(-6 * 30 * 24 * time.Hour), now.Add(6 * 30 * 24 * time.Hour), true},
		{"short duration", now.Add(-30 * time.Second), now.Add(30 * time.Second), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			caCert := &x509.Certificate{
				NotBefore: tc.notBefore,
				NotAfter:  tc.notAfter,
			}
			m := Manager{
				now: func() time.Time { return now },
				log: log,
			}

			jitteryDuration = func(float64) time.Duration { return time.Duration(float64(tc.notAfter.Sub(tc.notBefore)) * 0.7) }
			lowerBound := tc.notBefore.Add(time.Duration(float64(tc.notAfter.Sub(tc.notBefore)) * 0.7))

			deadline := m.nextRotationDeadlineForCert(caCert)

			if !deadline.Equal(lowerBound) {
				t.Errorf("For notBefore %v, notAfter %v, the rotationDeadline %v should be %v.",
					tc.notBefore,
					tc.notAfter,
					deadline,
					lowerBound)
			}
		})
	}
}

func TestVerifyTLS(t *testing.T) {

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

	secret := corev1.Secret{
		ObjectMeta: service.ObjectMeta,
	}

	newManager := func() *Manager {

		objs := []runtime.Object{mutatingWebhookConfiguration, service}

		client := fake.NewFakeClient(objs...)
		manager := NewManager(client, mutatingWebhookConfiguration.ObjectMeta.Name, MutatingWebhook, time.Hour)
		err := manager.rotate()
		if err != nil {
			t.Fatalf("rotate (%v)", err)
		}
		return manager
	}

	loadSecret := func(manager *Manager) {
		secretKey := types.NamespacedName{
			Namespace: secret.ObjectMeta.Namespace,
			Name:      secret.ObjectMeta.Name,
		}
		err := manager.client.Get(context.TODO(), secretKey, &secret)
		if err != nil {
			t.Fatalf("loadSecret (%v)", err)
		}
	}

	updateSecret := func(manager *Manager) {
		err := manager.client.Update(context.TODO(), &secret)
		if err != nil {
			t.Fatalf("updateSecret (%v)", err)
		}
	}

	deleteSecret := func(manager *Manager) {
		err := manager.client.Delete(context.TODO(), &secret)
		if err != nil {
			t.Fatalf("deleteSecret (%v)", err)
		}
	}

	loadMutatingWebhook := func(manager *Manager) {
		webhookKey := types.NamespacedName{
			Namespace: mutatingWebhookConfiguration.ObjectMeta.Namespace,
			Name:      mutatingWebhookConfiguration.ObjectMeta.Name,
		}
		err := manager.client.Get(context.TODO(), webhookKey, mutatingWebhookConfiguration)
		if err != nil {
			t.Fatalf("loadMutatingWebhook(%v)", err)
		}
	}

	updateMutatingWebhook := func(manager *Manager) {
		err := manager.client.Update(context.TODO(), mutatingWebhookConfiguration)
		if err != nil {
			t.Fatalf("updateMutatingWebhook(%v)", err)
		}
	}
	testCases := []struct {
		name       string
		test       func(manager *Manager)
		shouldFail bool
	}{
		{"when rotate is call, should not fail", func(m *Manager) {}, false},
		{"when secret deleted, should fail", func(m *Manager) {
			deleteSecret(m)
		}, true},
		{"when secret's private key is removed, should fail", func(m *Manager) {
			loadSecret(m)
			delete(secret.Data, corev1.TLSPrivateKeyKey)
			updateSecret(m)
		}, true},
		{"when secret's private key is not PEM, should fail", func(m *Manager) {
			loadSecret(m)
			secret.Data[corev1.TLSPrivateKeyKey] = []byte("This is not a PEM encoded key")
			updateSecret(m)
		}, true},
		{"when secret's certificate is removed, should fail", func(m *Manager) {
			loadSecret(m)
			delete(secret.Data, corev1.TLSCertKey)
			updateSecret(m)
		}, true},
		{"when secret's certificate is not PEM, should fail", func(m *Manager) {
			loadSecret(m)
			secret.Data[corev1.TLSCertKey] = []byte("This is not a PEM encoded key")
			updateSecret(m)
		}, true},
		{"when mutatingWebhookConfiguration CABundle is removed, should fail", func(m *Manager) {
			loadMutatingWebhook(m)
			mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = nil
			updateMutatingWebhook(m)
		}, true},
		{"when mutatingWebhookConfiguration CABundle is empty, should fail", func(m *Manager) {
			loadMutatingWebhook(m)
			mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte{}
			updateMutatingWebhook(m)
		}, true},
		{"when mutatingWebhookConfiguration CABundle is not PEM formated, should fail", func(m *Manager) {
			loadMutatingWebhook(m)
			mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte("This is not a CABundle PEM")
			updateMutatingWebhook(m)
		}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager := newManager()
			tc.test(manager)
			err := manager.verifyTLS()
			if tc.shouldFail {
				if err == nil {
					t.Fatal("should fail")
				}
			} else {
				if err != nil {
					t.Fatalf("should not fail (%v)", err)
				}
			}
		})
	}
}
