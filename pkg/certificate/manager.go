package certificate

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

// Manager do the CA and service certificate/key generation and expiration
// handling.
// It will generate one CA for the webhook configuration and a
// secret per Service referenced on it. One unique instance has to run at
// at cluster to monitor expiration time and do rotations.
type Manager struct {
	// client contains the controller-runtime client from the manager.
	client client.Client

	// webhookName The Mutating or Validating Webhook configuration name
	webhookName string

	// webhookType The Mutating or Validating Webhook configuration type
	webhookType WebhookType

	// The namespace where ca secret will be created or service secrets
	// for ClientConfig that has URL instead of ServiceRef
	namespace string

	// now is an artifact to do some unit testing without waiting for
	// expiration time.
	now func() time.Time

	// lastRotateDeadline store the value of last call from nextRotationDeadline
	lastRotateDeadline *time.Time

	// lastRotateDeadlineForServices store the value of last call from nextRotationDeadlineForServices
	lastRotateDeadlineForServices *time.Time

	// caCertDuration configurated duration for CA and certificate
	caCertDuration time.Duration

	// serviceCertDuration configurated duration for of service certificate
	// the the webhook configuration is referencing different services all
	// of them will share the same duration
	serviceCertDuration time.Duration

	// log initialized log that containes the webhook configuration name and
	// namespace so it's easy to debug.
	log logr.Logger
}

type WebhookType string

const (
	MutatingWebhook   WebhookType = "Mutating"
	ValidatingWebhook WebhookType = "Validating"
	OneYearDuration               = 365 * 24 * time.Hour
)

// NewManager with create a certManager that generated a secret per service
// at the webhook TLS http server.
// It will also starts at cert manager [1] that will update them if they expire.
// The generate certificate include the following fields:
// DNSNames (for every service the webhook refers too):
//	   - ${service.Name}
//	   - ${service.Name}.${service.namespace}
//	   - ${service.Name}.${service.namespace}.svc
// Subject:
// 	  - CN: ${webhookName}
// Usages:
//	   - UsageDigitalSignature
//	   - UsageKeyEncipherment
//	   - UsageServerAuth
//
// It will also update the webhook caBundle field with the cluster CA cert and
// approve the generated cert/key with k8s certification approval mechanism
func NewManager(
	client client.Client,
	webhookName string,
	webhookType WebhookType,
	namespace string,
	caCertDuration time.Duration,
	serviceCertDuration time.Duration,
) *Manager {

	m := &Manager{
		client:               client,
		webhookName:          webhookName,
		webhookType:          webhookType,
		namespace:            namespace,
		now:                  time.Now,
		caCertDuration:       caCertDuration,
		serviceCertDuration: serviceCertDuration,
		log: logf.Log.WithName("certificate/manager").
			WithValues("webhookType", webhookType, "webhookName", webhookName),
	}
	return m
}

func (m *Manager) getCACertsFromCABundle() ([]*x509.Certificate, error) {
	caBundle, err := m.CABundle()
	if err != nil {
		return nil, errors.Wrap(err, "failed getting CABundle")
	}

	if len(caBundle) == 0 {
		return nil, nil
	}

	cas, err := triple.ParseCertsPEM(caBundle)
	if err != nil {
		return nil, errors.Wrap(err, "failed parsing PEM CABundle")
	}
	return cas, nil
}

func (m *Manager) getLastAppendedCACertFromCABundle() (*x509.Certificate, error) {
	cas, err := m.getCACertsFromCABundle()
	if err != nil {
		return nil, errors.Wrap(err, "failed getting CA certificates from CA bundle")
	}
	if len(cas) == 0 {
		return nil, nil
	}
	return cas[len(cas)-1], nil
}

func (m *Manager) rotateAll() error {
	m.log.Info("Rotating CA cert/key")

	caKeyPair, err := triple.NewCA(m.webhookName, m.caCertDuration)
	if err != nil {
		return errors.Wrap(err, "failed generating CA cert/key")
	}

	err = m.addCertificateToCABundle(caKeyPair.Cert)
	if err != nil {
		return errors.Wrap(err, "failed adding new CA cert to CA bundle at webhook")
	}

	err = m.applyCASecret(caKeyPair)
	if err != nil {
		return errors.Wrap(err, "failed storing CA cert/key at secret")
	}

	err = m.rotateServices()
	if err != nil {
		return errors.Wrap(err, "failed rotating services")
	}

	return nil
}

func (m *Manager) rotateServices() error {
	m.log.Info("Rotating CA cert/key")

	webhook, err := m.readyWebhookConfiguration()
	if err != nil {
		return errors.Wrap(err, "failed reading webhook configuration at services rotation")
	}

	services, err := m.getServicesFromConfiguration(webhook)
	if err != nil {
		return errors.Wrap(err, "failed retrieving services from clientConfig")
	}

	caKeyPair, err := m.getCAKeyPair()
	if err != nil {
		return errors.Wrap(err, "failed getting CA key pair")
	}

	for service, hostnames := range services {
		keyPair, err := triple.NewServerKeyPair(
			caKeyPair,
			service.Name+"."+service.Namespace+".pod.cluster.local",
			service.Name,
			service.Namespace,
			"cluster.local",
			nil,
			hostnames,
			m.serviceCertDuration,
		)
		if err != nil {
			return errors.Wrapf(err, "failed creating server key/cert for service %+v", service)
		}
		err = m.applyTLSSecret(service, keyPair)
		if err != nil {
			return errors.Wrapf(err, "failed applying TLS secret %s", service)
		}
	}

	return nil
}

// nextRotationDeadlineForService will look at the first service at
// webhook configuration find the secret's TLS certificate and calculate
// next deadline, looking at first serices is fine since they certificates
// are created/rotated at the same time
func (m *Manager) nextRotationDeadlineForServices() time.Time {
	webhookConf, err := m.readyWebhookConfiguration()
	if err != nil {
		m.log.Info(fmt.Sprintf("failed getting webhook configuration, forcing rotation: %v", err))
		return m.now()
	}

	services, err := m.getServicesFromConfiguration(webhookConf)
	if err != nil {
		m.log.Info(fmt.Sprintf("failed getting webhook configuration services, forcing rotation: %v", err))
		return m.now()
	}

	// Iterate the `services` map to calculate deadline with the first
	// occurrence
	for service, _ := range services {

		tlsKeyPair, err := m.getTLSKeyPair(service)
		if err != nil {
			m.log.Info(fmt.Sprintf("failed getting TLS keypair from service %s , forcing rotation: %v", service, err))
			return m.now()
		}

		nextDeadline := m.nextRotationDeadlineForCert(tlsKeyPair.Cert)

		// Store last calculated deadline to use it at Reconcile
		m.lastRotateDeadlineForServices = &nextDeadline
		return nextDeadline
	}
	return m.now()
}

// nextRotationDeadline returns a value for the threshold at which the
// current certificate should be rotated, 80%+/-10% of the expiration of the
// certificate or force rotation in case the certificate chain is faulty
func (m *Manager) nextRotationDeadline() time.Time {
	err := m.verifyTLS()
	if err != nil {
		// Sprintf is used to prevent stack trace to be printed
		m.log.Info(fmt.Sprintf("Bad TLS certificate chain, forcing rotation: %v", err))
		return m.now()
	}

	// Last rotated CA cert at CABundle is the last at the slice so this
	// calculate deadline from it.
	caCert, err := m.getLastAppendedCACertFromCABundle()
	if err != nil {
		m.log.Info("Failed reading last CA cert from CABundle, forcing rotation", "err", err)
		return m.now()
	}
	nextDeadline := m.nextRotationDeadlineForCert(caCert)

	// Store last calculated deadline to use it at Reconcile
	m.lastRotateDeadline = &nextDeadline
	return nextDeadline
}

// nextRotationDeadlineForCert returns a value for the threshold at which the
// current certificate should be rotated, 80%+/-10% of the expiration of the
// certificate
func (m *Manager) nextRotationDeadlineForCert(certificate *x509.Certificate) time.Time {
	notAfter := certificate.NotAfter
	totalDuration := float64(notAfter.Sub(certificate.NotBefore))
	deadline := certificate.NotBefore.Add(jitteryDuration(totalDuration))

	m.log.Info(fmt.Sprintf("Certificate expiration is %v, totalDuration is %v, rotation deadline is %v", notAfter, totalDuration, deadline))
	return deadline
}

func (m *Manager) elapsedToRotateCAFromLastDeadline() time.Duration {
	deadline := m.now()

	// If deadline was previously calculated return it, else do the
	// calculations
	if m.lastRotateDeadline != nil {
		deadline = *m.lastRotateDeadline
	} else {
		deadline = m.nextRotationDeadline()
	}
	now := m.now()
	elapsedToRotate := deadline.Sub(now)
	m.log.Info(fmt.Sprintf("elapsedToRotateCAFromLastDeadline {now: %s, deadline: %s, elapsedToRotate: %s}", now, deadline, elapsedToRotate))
	return elapsedToRotate
}

func (m *Manager) elapsedToRotateServicesFromLastDeadline() time.Duration {
	deadline := m.now()

	// If deadline was previously calculated return it, else do the
	// calculations
	if m.lastRotateDeadlineForServices != nil {
		deadline = *m.lastRotateDeadlineForServices
	} else {
		deadline = m.nextRotationDeadlineForServices()
	}
	now := m.now()
	elapsedToRotate := deadline.Sub(now)
	m.log.Info(fmt.Sprintf("elapsedToRotateServicesFromLastDeadline{now: %s, deadline: %s, elapsedToRotate: %s}", now, deadline, elapsedToRotate))
	return elapsedToRotate
}

// verifyTLS will verify that the caBundle and Secret are valid and can
// be used to verify
func (m *Manager) verifyTLS() error {

	webhookConf, err := m.readyWebhookConfiguration()
	if err != nil {
		return errors.Wrap(err, "failed to reading configuration")
	}

	caKeyPair, err := m.getCAKeyPair()
	if err != nil {
		return errors.Wrap(err, "failed getting CA keypair from secret to verify TLS")
	}

	for _, clientConfig := range m.clientConfigList(webhookConf) {
		service := clientConfig.Service
		secretKey := types.NamespacedName{}
		if service != nil {
			// If the webhook has a service then create the secret
			// with same namespce and name
			secretKey.Name = service.Name
			secretKey.Namespace = service.Namespace
		} else {
			// If it uses directly URL create a secret with webhookName and
			// mgr namespace
			secretKey.Name = m.webhookName
			secretKey.Namespace = m.namespace
		}
		err = m.verifyTLSSecret(secretKey, caKeyPair, clientConfig.CABundle)
		if err != nil {
			return errors.Wrapf(err, "failed verifying TLS secret %s", secretKey)
		}
	}

	return nil
}

// jitteryDuration uses some jitter to set the rotation threshold so each node
// will rotate at approximately 70-90% of the total lifetime of the
// certificate.  With jitter, if a number of nodes are added to a cluster at
// approximately the same time (such as cluster creation time), they won't all
// try to rotate certificates at the same time for the rest of the life of the
// cluster.
//
// This function is represented as a variable to allow replacement during testing.
var jitteryDuration = func(totalDuration float64) time.Duration {
	return wait.Jitter(time.Duration(totalDuration), 0.2) - time.Duration(totalDuration*0.3)
}
