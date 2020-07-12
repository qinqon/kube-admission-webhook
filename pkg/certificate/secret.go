package certificate

import (
	"context"

	"github.com/pkg/errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

const (
	secretManagedAnnotatoinKey = "kubevirt.io/kube-admission-webhook"
	CACertKey                  = "ca.crt"
	CAPrivateKeyKey            = "ca.key"
)

func populateCASecret(secret corev1.Secret, keyPair *triple.KeyPair) *corev1.Secret {
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[secretManagedAnnotatoinKey] = ""
	secret.Data = map[string][]byte{
		CACertKey:       triple.EncodeCertPEM(keyPair.Cert),
		CAPrivateKeyKey: triple.EncodePrivateKeyPEM(keyPair.Key),
	}
	secret.Type = corev1.SecretTypeOpaque
	return &secret
}

func populateTLSSecret(secret corev1.Secret, keyPair *triple.KeyPair) *corev1.Secret {
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[secretManagedAnnotatoinKey] = ""
	secret.Data = map[string][]byte{
		corev1.TLSCertKey:       triple.EncodeCertPEM(keyPair.Cert),
		corev1.TLSPrivateKeyKey: triple.EncodePrivateKeyPEM(keyPair.Key),
	}
	secret.Type = corev1.SecretTypeTLS
	return &secret
}

func (m *Manager) applyTLSSecret(secret types.NamespacedName, keyPair *triple.KeyPair) error {
	return m.applySecret(secret, keyPair, populateTLSSecret)
}

func (m *Manager) applyCASecret(secret types.NamespacedName, keyPair *triple.KeyPair) error {
	return m.applySecret(secret, keyPair, populateCASecret)
}

func (m *Manager) applySecret(secretKey types.NamespacedName, keyPair *triple.KeyPair,
	populateSecretFn func(corev1.Secret, *triple.KeyPair) *corev1.Secret) error {
	secret := corev1.Secret{}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := m.get(secretKey, &secret)
		if err != nil {
			if apierrors.IsNotFound(err) {
				newSecret := corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:        secretKey.Name,
						Namespace:   secretKey.Namespace,
						Annotations: map[string]string{},
					},
				}
				err = m.client.Create(context.TODO(), populateSecretFn(newSecret, keyPair))
				if err != nil {
					return errors.Wrap(err, "failed creating secret")
				}
				return nil
			} else {
				return err
			}
		}
		err = m.client.Update(context.TODO(), populateSecretFn(secret, keyPair))
		if err != nil {
			return errors.Wrap(err, "failed updating secret")
		}
		return nil
	})
}

// verifyTLSSecret will verify that the caBundle and Secret are valid and can
// be used to verify
func (m *Manager) verifyTLSSecret(secretKey types.NamespacedName, caBundle []byte) error {
	secret := corev1.Secret{}
	err := m.get(secretKey, &secret)
	if err != nil {
		return errors.Wrapf(err, "failed getting TLS secret %s", secretKey)
	}

	keyPEM, found := secret.Data[corev1.TLSPrivateKeyKey]
	if !found {
		return errors.New("TLS key not found")
	}

	certsPEM, found := secret.Data[corev1.TLSCertKey]
	if !found {
		return errors.New("TLS certs not found")
	}

	err = triple.VerifyTLS(certsPEM, keyPEM, []byte(caBundle))
	if err != nil {
		return errors.Wrapf(err, "failed verifying TLS from server Secret %s", secretKey)
	}

	return nil
}
