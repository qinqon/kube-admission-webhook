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
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

var _ = Describe("certificate manager", func() {
	type nextRotationDeadlineForCertCase struct {
		notBefore    time.Duration
		notAfter     time.Duration
		shouldRotate bool
	}
	DescribeTable("nextRotationDeadlineForCert",
		func(c nextRotationDeadlineForCertCase) {
			log := logf.Log.WithName("webhook/server/certificate/manager_test")
			now := time.Now()
			notAfter := now.Add(c.notAfter)
			notBefore := now.Add(c.notBefore)
			defer func(original func(float64) time.Duration) { jitteryDuration = original }(jitteryDuration)
			caCert := &x509.Certificate{
				NotBefore: notBefore,
				NotAfter:  notAfter,
			}
			m := Manager{
				now: func() time.Time { return now },
				log: log,
			}
			triple.Now = m.now
			jitteryDuration = func(float64) time.Duration { return time.Duration(float64(notAfter.Sub(notBefore)) * 0.7) }
			lowerBound := notBefore.Add(time.Duration(float64(notAfter.Sub(notBefore)) * 0.7))

			deadline := m.nextRotationDeadlineForCert(caCert)

			Expect(deadline).To(Equal(lowerBound), fmt.Sprintf("should match deadline for notBefore %v and notAfter %v", notBefore, notAfter))

		},
		Entry("just issued, still good", nextRotationDeadlineForCertCase{
			notBefore:    -1 * time.Hour,
			notAfter:     99 * time.Hour,
			shouldRotate: false,
		}),
		Entry("half way expired, still good", nextRotationDeadlineForCertCase{
			notBefore:    -24 * time.Hour,
			notAfter:     24 * time.Hour,
			shouldRotate: false,
		}),
		Entry("mostly expired, still good", nextRotationDeadlineForCertCase{
			notBefore:    -69 * time.Hour,
			notAfter:     31 * time.Hour,
			shouldRotate: false,
		}),
		Entry("just about expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -91 * time.Hour,
			notAfter:     9 * time.Hour,
			shouldRotate: true,
		}),
		Entry("nearly expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -99 * time.Hour,
			notAfter:     1 * time.Hour,
			shouldRotate: true,
		}),
		Entry("already expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -10 * time.Hour,
			notAfter:     -1 * time.Hour,
			shouldRotate: true,
		}),
		Entry("long duration", nextRotationDeadlineForCertCase{
			notBefore:    -6 * 30 * 24 * time.Hour,
			notAfter:     6 * 30 * 24 * time.Hour,
			shouldRotate: true,
		}),
		Entry("short duration", nextRotationDeadlineForCertCase{
			notBefore:    -30 * time.Second,
			notAfter:     30 * time.Second,
			shouldRotate: true,
		}),
	)

	type verifyTLSTestCase struct {
		certificatesChain func(manager *Manager)
		shouldFail        bool
	}

	newManager := func() *Manager {

		manager := NewManager(cli, expectedMutatingWebhookConfiguration.ObjectMeta.Name, MutatingWebhook, time.Hour)
		err := manager.rotateAll()
		ExpectWithOffset(1, err).To(Succeed(), "should success rotating certs")

		return manager
	}
	loadSecret := func(manager *Manager) corev1.Secret {
		secretKey := types.NamespacedName{
			Namespace: expectedSecret.ObjectMeta.Namespace,
			Name:      expectedSecret.ObjectMeta.Name,
		}
		obtainedSecret := corev1.Secret{}
		err := manager.client.Get(context.TODO(), secretKey, &obtainedSecret)
		ExpectWithOffset(1, err).To(Succeed(), "should success getting secrets")
		return obtainedSecret
	}
	updateSecret := func(manager *Manager, secretToUpdate *corev1.Secret) {
		err := manager.client.Update(context.TODO(), secretToUpdate)
		ExpectWithOffset(1, err).To(Succeed(), "should success updating secret")
	}

	deleteSecret := func(manager *Manager, secretToDelete *corev1.Secret) {
		err := manager.client.Delete(context.TODO(), secretToDelete)
		ExpectWithOffset(1, err).To(Succeed(), "should success deleting secret")
	}

	loadMutatingWebhook := func(manager *Manager) admissionregistrationv1beta1.MutatingWebhookConfiguration {
		webhookKey := types.NamespacedName{
			Namespace: expectedMutatingWebhookConfiguration.ObjectMeta.Namespace,
			Name:      expectedMutatingWebhookConfiguration.ObjectMeta.Name,
		}
		obtainedMutatingWebhookConfiguration := admissionregistrationv1beta1.MutatingWebhookConfiguration{}
		err := manager.client.Get(context.TODO(), webhookKey, &obtainedMutatingWebhookConfiguration)
		ExpectWithOffset(1, err).To(Succeed(), "should success getting mutatingwebhookconfiguration")
		return obtainedMutatingWebhookConfiguration
	}

	updateMutatingWebhook := func(manager *Manager, mutatingWebhookConfigurationToUpdate *admissionregistrationv1beta1.MutatingWebhookConfiguration) {
		err := manager.client.Update(context.TODO(), mutatingWebhookConfigurationToUpdate)
		ExpectWithOffset(1, err).To(Succeed(), "should success updating mutatingwebhookconfiguration")
	}

	DescribeTable("VerifyTLS",
		func(c verifyTLSTestCase) {
			createResources()
			defer deleteResources()
			manager := newManager()
			c.certificatesChain(manager)
			err := manager.verifyTLS()
			if c.shouldFail {
				Expect(err).To(HaveOccurred(), "should fail VerifyTLS")
			} else {
				Expect(err).To(Succeed(), "should success VerifyTLS")
			}
		},
		Entry("when rotate is call, should not fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {},
			shouldFail:        false,
		}),

		Entry("when secret deleted, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				deleteSecret(m, &expectedSecret)
			},
			shouldFail: true,
		}),
		Entry("when secret's private key is not PEM, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedSecret := loadSecret(m)
				obtainedSecret.Data[corev1.TLSPrivateKeyKey] = []byte("This is not a PEM encoded key")
				updateSecret(m, &obtainedSecret)
			},
			shouldFail: true,
		}),
		Entry("when secret's certificate is not PEM, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedSecret := loadSecret(m)
				obtainedSecret.Data[corev1.TLSCertKey] = []byte("This is not a PEM encoded key")
				updateSecret(m, &obtainedSecret)
			},
			shouldFail: true,
		}),
		Entry("when mutatingWebhookConfiguration CABundle is removed, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedMutatingWebhookConfiguration := loadMutatingWebhook(m)
				obtainedMutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = nil
				updateMutatingWebhook(m, &obtainedMutatingWebhookConfiguration)
			},
			shouldFail: true,
		}),
		Entry("when mutatingWebhookConfiguration CABundle is empty, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedMutatingWebhookConfiguration := loadMutatingWebhook(m)
				obtainedMutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte{}
				updateMutatingWebhook(m, &obtainedMutatingWebhookConfiguration)
			},
			shouldFail: true,
		}),
		Entry("when mutatingWebhookConfiguration CABundle is not PEM formated, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedMutatingWebhookConfiguration := loadMutatingWebhook(m)
				obtainedMutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte("This is not a CABundle PEM")
				updateMutatingWebhook(m, &obtainedMutatingWebhookConfiguration)
			},
			shouldFail: true,
		}),
	)
})
