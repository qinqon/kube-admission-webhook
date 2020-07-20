package certificate

import (
	"context"
	"crypto/rsa"
	"reflect"

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
	return &secret
}

func (m *Manager) applyTLSSecret(secret types.NamespacedName, keyPair *triple.KeyPair) error {
	return m.applySecret(secret, corev1.SecretTypeTLS, keyPair, populateTLSSecret)
}

func (m *Manager) applyCASecret(secret types.NamespacedName, keyPair *triple.KeyPair) error {
	return m.applySecret(secret, corev1.SecretTypeOpaque, keyPair, populateCASecret)
}

func (m *Manager) applySecret(secretKey types.NamespacedName, secretType corev1.SecretType, keyPair *triple.KeyPair,
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
					Type: secretType,
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
func (m *Manager) verifyTLSSecret(secretKey types.NamespacedName, caKeyPair *triple.KeyPair, caBundle []byte) error {
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

	certsFromCABundle, err := triple.ParseCertsPEM(caBundle)
	if err != nil {
		return errors.Wrap(err, "failed parsing CABundle as pem encoded certificates")
	}

	if len(certsFromCABundle) == 0 {
		return errors.New("CA bundle has no certificates")
	}

	lastCertFromCABundle := certsFromCABundle[len(certsFromCABundle)-1]

	if !reflect.DeepEqual(*lastCertFromCABundle, *caKeyPair.Cert) {
		return errors.New("CA bundle and CA secret certificate are different")
	}

	err = triple.VerifyTLS(certsPEM, keyPEM, caBundle)
	if err != nil {
		return errors.Wrapf(err, "failed verifying TLS from server Secret %s", secretKey)
	}

	return nil
}

func (m *Manager) getCAKeyPair() (*triple.KeyPair, error) {
	secret := corev1.Secret{}
	caSecretKey := types.NamespacedName{Namespace: "default", Name: m.webhookName}
	err := m.get(caSecretKey, &secret)
	if err != nil {
		return nil, errors.Wrapf(err, "failed reading ca secret %s", caSecretKey)
	}

	caPrivateKeyPEM, found := secret.Data[CAPrivateKeyKey]
	if !found {
		return nil, errors.Wrapf(err, "ca private key not found at secret %s", caSecretKey)
	}

	caCertPEM, found := secret.Data[CACertKey]
	if !found {
		return nil, errors.Wrapf(err, "ca cert not found at secret %s", caSecretKey)
	}

	caCerts, err := triple.ParseCertsPEM(caCertPEM)
	if err != nil {
		return nil, errors.Wrapf(err, "failed parsing ca cert PEM at secret %s", caSecretKey)
	}

	caPrivateKey, err := triple.ParsePrivateKeyPEM(caPrivateKeyPEM)
	if err != nil {
		return nil, errors.Wrapf(err, "failed parsing ca private key PEM at secret %s", caSecretKey)
	}
	return &triple.KeyPair{Key: caPrivateKey.(*rsa.PrivateKey), Cert: caCerts[0]}, nil
}
