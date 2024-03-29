/*
 * Copyright 2022 Kube Admission Webhook Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certificate

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

var _ = Describe("certificate manager", func() {
	type nextRotationDeadlineForCertCase struct {
		notBefore    time.Duration
		notAfter     time.Duration
		overlap      time.Duration
		shouldRotate bool
	}
	DescribeTable("nextRotationDeadlineForCert",
		func(c nextRotationDeadlineForCertCase) {
			log := logf.Log.WithName("webhook/server/certificate/manager_test")
			now := time.Now()
			notAfter := now.Add(c.notAfter)
			notBefore := now.Add(c.notBefore)
			caCert := &x509.Certificate{
				NotBefore: notBefore,
				NotAfter:  notAfter,
			}
			m := Manager{
				now: func() time.Time { return now },
				log: log,
			}
			triple.Now = m.now

			lowerBound := notBefore.Add(notAfter.Sub(notBefore) - c.overlap)

			deadline := m.nextRotationDeadlineForCert(caCert, c.overlap)

			Expect(deadline).To(Equal(lowerBound),
				fmt.Sprintf("should match deadline for notBefore %v, notAfter %v and overlap %v", notBefore, notAfter, c.overlap))

		},
		Entry("just issued, still good", nextRotationDeadlineForCertCase{
			notBefore:    -1 * time.Hour,
			notAfter:     99 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: false,
		}),
		Entry("half way expired, still good", nextRotationDeadlineForCertCase{
			notBefore:    -24 * time.Hour,
			notAfter:     24 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: false,
		}),
		Entry("mostly expired, still good", nextRotationDeadlineForCertCase{
			notBefore:    -69 * time.Hour,
			notAfter:     31 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: false,
		}),
		Entry("just about expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -91 * time.Hour,
			notAfter:     9 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: true,
		}),
		Entry("nearly expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -99 * time.Hour,
			notAfter:     1 * time.Hour,
			overlap:      10 * time.Hour,
			shouldRotate: true,
		}),
		Entry("already expired, should rotate", nextRotationDeadlineForCertCase{
			notBefore:    -10 * time.Hour,
			notAfter:     -1 * time.Hour,
			overlap:      10 * time.Hour,
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

	genericNewManager := func(labels map[string]string) *Manager {
		options := Options{
			WebhookName: expectedMutatingWebhookConfiguration.ObjectMeta.Name,
			WebhookType: MutatingWebhook, Namespace: expectedNamespace.Name,
			CARotateInterval:   time.Hour,
			CertRotateInterval: time.Hour,
		}
		if labels != nil {
			options.ExtraLabels = labels
		}

		manager, err := NewManager(cli, &options)
		ExpectWithOffset(2, err).To(Succeed(), "should success creating certificate manager")
		err = manager.rotateAll()
		ExpectWithOffset(2, err).To(Succeed(), "should success rotating certs")

		return manager
	}

	newManager := func() *Manager {
		return genericNewManager(nil)
	}

	const expectedLabelKey = "foo"
	const expectedLabelValue = "bar"
	newManagerWithLabels := func() *Manager {
		return genericNewManager(map[string]string{expectedLabelKey: expectedLabelValue})
	}

	loadServiceSecret := func(manager *Manager) corev1.Secret {
		secretKey := types.NamespacedName{
			Namespace: expectedSecret.ObjectMeta.Namespace,
			Name:      expectedSecret.ObjectMeta.Name,
		}
		obtainedSecret := corev1.Secret{}
		err := manager.client.Get(context.TODO(), secretKey, &obtainedSecret)
		ExpectWithOffset(1, err).To(Succeed(), "should success getting secrets")
		return obtainedSecret
	}

	loadCASecret := func(manager *Manager) corev1.Secret {
		secretKey := types.NamespacedName{
			Namespace: expectedCASecret.Namespace,
			Name:      expectedCASecret.Name,
		}
		obtainedSecret := corev1.Secret{}
		err := manager.client.Get(context.TODO(), secretKey, &obtainedSecret)
		ExpectWithOffset(1, err).To(Succeed(), "should success getting CA secrets")
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

	loadMutatingWebhook := func(manager *Manager) admissionregistrationv1.MutatingWebhookConfiguration {
		webhookKey := types.NamespacedName{
			Namespace: expectedMutatingWebhookConfiguration.ObjectMeta.Namespace,
			Name:      expectedMutatingWebhookConfiguration.ObjectMeta.Name,
		}
		obtainedMutatingWebhookConfiguration := admissionregistrationv1.MutatingWebhookConfiguration{}
		err := manager.client.Get(context.TODO(), webhookKey, &obtainedMutatingWebhookConfiguration)
		ExpectWithOffset(1, err).To(Succeed(), "should success getting mutatingwebhookconfiguration")
		return obtainedMutatingWebhookConfiguration
	}

	updateMutatingWebhook := func(manager *Manager,
		mutatingWebhookConfigurationToUpdate *admissionregistrationv1.MutatingWebhookConfiguration) {
		err := manager.client.Update(context.TODO(), mutatingWebhookConfigurationToUpdate)
		ExpectWithOffset(1, err).To(Succeed(), "should success updating mutatingwebhookconfiguration")
	}

	Context("when secrets are created", func() {
		BeforeEach(func() {
			createResources()
		})
		AfterEach(func() {
			deleteResources()
		})
		Context("without extra labels option", func() {
			var manager *Manager
			BeforeEach(func() {
				manager = newManager()
			})
			It("should not have extra labels", func() {
				obtainedCASecret := loadCASecret(manager)
				Expect(obtainedCASecret.GetLabels()).To(BeEmpty())
				obtainedSecret := loadServiceSecret(manager)
				Expect(obtainedSecret.GetLabels()).To(BeEmpty())
			})
		})

		Context("with extra labels option", func() {
			var manager *Manager
			BeforeEach(func() {
				manager = newManagerWithLabels()
			})
			It("should have extra labels", func() {
				obtainedCASecret := loadCASecret(manager)
				Expect(obtainedCASecret.GetLabels()).To(HaveKeyWithValue(expectedLabelKey, expectedLabelValue))
				obtainedSecret := loadServiceSecret(manager)
				Expect(obtainedSecret.GetLabels()).To(HaveKeyWithValue(expectedLabelKey, expectedLabelValue))
			})
		})
	})

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
		Entry("when CA secret deleted, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				deleteSecret(m, &expectedCASecret)
			},
			shouldFail: true,
		}),

		Entry("when secret's private key is not PEM, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedSecret := loadServiceSecret(m)
				obtainedSecret.Data[corev1.TLSPrivateKeyKey] = []byte("This is not a PEM encoded key")
				updateSecret(m, &obtainedSecret)
			},
			shouldFail: true,
		}),
		Entry("when secret's certificate is not PEM, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedSecret := loadServiceSecret(m)
				obtainedSecret.Data[corev1.TLSCertKey] = []byte("This is not a PEM encoded key")
				updateSecret(m, &obtainedSecret)
			},
			shouldFail: true,
		}),

		Entry("when CA secret's private key is not PEM, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedSecret := loadCASecret(m)
				obtainedSecret.Data[CAPrivateKeyKey] = []byte("This is not a PEM encoded key")
				updateSecret(m, &obtainedSecret)
			},
			shouldFail: true,
		}),

		Entry("when CA secret's certificate is not PEM, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				obtainedSecret := loadCASecret(m)
				obtainedSecret.Data[CACertKey] = []byte("This is not a PEM encoded key")
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
		Entry("when mutatingWebhookConfiguration CABundle last certificate is not the same as CA secret, should fail", verifyTLSTestCase{
			certificatesChain: func(m *Manager) {
				hackedCA, err := triple.NewCA("hacked-ca", 100*OneYearDuration)
				Expect(err).To(Succeed(), "should succeed creating new hacked CA")

				obtainedMutatingWebhookConfiguration := loadMutatingWebhook(m)
				caBundle := obtainedMutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle
				hackedCABundle := append(triple.EncodeCertPEM(hackedCA.Cert), caBundle...)
				obtainedMutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = hackedCABundle
				updateMutatingWebhook(m, &obtainedMutatingWebhookConfiguration)
			},
			shouldFail: true,
		}),
	)
})
