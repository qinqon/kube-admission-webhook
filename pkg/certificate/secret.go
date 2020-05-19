package certificate

import (
	"context"
	"crypto/x509"

	"github.com/pkg/errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

func updateTLSSecret(secret corev1.Secret, keyPair *triple.KeyPair) *corev1.Secret {
	secret.Data = map[string][]byte{
		corev1.TLSCertKey:       triple.EncodeCertPEM(keyPair.Cert),
		corev1.TLSPrivateKeyKey: triple.EncodePrivateKeyPEM(keyPair.Key),
	}
	secret.Type = corev1.SecretTypeTLS
	return &secret
}

func (m *Manager) newTLSSecret(serviceKey types.NamespacedName, keyPair *triple.KeyPair) (*corev1.Secret, error) {
	service := corev1.Service{}
	err := m.get(serviceKey, &service)
	if err != nil {
		return nil, errors.Wrapf(err, "failed getting service %s to set secret owner", serviceKey)
	}

	serviceGVK, err := apiutil.GVKForObject(&service, scheme.Scheme)
	if err != nil {
		return nil, errors.Wrapf(err, "failed getting gvk from service %s", serviceKey)
	}

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.Name,
			Namespace: service.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					Name:       service.Name,
					Kind:       serviceGVK.Kind,
					APIVersion: serviceGVK.GroupVersion().String(),
					UID:        service.UID},
			},
		},
	}
	return updateTLSSecret(secret, keyPair), nil
}

func (m *Manager) applyTLSSecret(service types.NamespacedName, keyPair *triple.KeyPair) error {
	secret := corev1.Secret{}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := m.get(service, &secret)
		if err != nil {
			if apierrors.IsNotFound(err) {
				tlsSecret, err := m.newTLSSecret(service, keyPair)
				if err != nil {
					return errors.Wrapf(err, "failed initailizing secret %s", service)
				}
				return m.client.Create(context.TODO(), tlsSecret)
			} else {
				return err
			}
		}
		return m.client.Update(context.TODO(), updateTLSSecret(secret, keyPair))
	})
}

// checkTLS will verify that the caBundle and Secret are valid and can
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

	_, err = triple.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return errors.Wrap(err, "failed parsing PEM TLS key")
	}

	certsPEM, found := secret.Data[corev1.TLSCertKey]
	if !found {
		return errors.New("TLS certs not found")
	}

	certs, err := triple.ParseCertsPEM(certsPEM)
	if err != nil {
		return errors.Wrap(err, "failed parsing PEM TLS certs")
	}

	cas := x509.NewCertPool()
	ok := cas.AppendCertsFromPEM([]byte(caBundle))
	if !ok {
		return errors.New("failed to parse CA bundle")
	}

	opts := x509.VerifyOptions{
		Roots:   cas,
		DNSName: certs[0].DNSNames[0],
	}

	if _, err := certs[0].Verify(opts); err != nil {
		return errors.Wrap(err, "failed to verify certificate")
	}

	return nil
}
