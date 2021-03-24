package certificate

import (
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/chain"
	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

// Manager that does certificate/key generation and expiration
// handling of services backing a set of webhooks and of a corresponding
// CA.
type Manager struct {

	// name
	name string

	// namespace
	namespace string

	// client contains the controller-runtime client from the manager.
	client client.Client

	// webhooks
	webhooks []WebhookReference

	// options
	options chain.Options

	active sync.Mutex
	verifying bool

	// log initialized log that containes the webhook configuration name and
	// namespace so it's easy to debug.
	log logr.Logger
}

// NewManager with create a Manager that generates and updates at expiration a secret
// containing certificates per service backing the set of webhooks provided.
// These secrets name will be the same as the service.
// The generate certificate include the following fields:
// DNSNames (for every service the webhook refers too):
//	   - ${service.Name}
//	   - ${service.Name}.${service.namespace}
//	   - ${service.Name}.${service.namespace}.svc
//     - ${service.Name}.${service.namespace}.svc
//     - ${service.Name}.${service.namespace}.svc.cluster.local
// Subject:
// 	  - CN: ${service.Name}.${service.namespace}.svc
// Usages:
//	   - UsageServerAuth
//
// It will also update the webhook caBundle field with the CA certificates used
// to issue the service certificates.
func NewManager(name string, namespace string, client client.Client, options chain.Options, webhooks []WebhookReference) (*Manager, error) {
	err := options.SetDefaultsAndValidate()
	if err != nil {
		return nil, err
	}

	m := &Manager{
		name:      name,
		namespace: namespace,
		client:    client,
		options:   options,
		webhooks:  webhooks,
		log:       logf.Log.WithName("certificate/Manager"),
	}
	return m, nil
}

// reconcileCertificates checks, updates and cleans up the certificate chain
// associated to the existing webhook configurations provided to this manager.
func (m *Manager) reconcileCertificates() (time.Duration, error) {
	logger := m.log.WithName("reconcileCertificates")
	m.active.Lock()
	defer m.active.Unlock()

	logger.Info("Reconciling webhook certificates")
	objects := objectMap{}
	certificateChain := chain.CertificateChainData{}

	err := m.readCertificateChain(objects, &certificateChain)
	if err != nil {
		return 0, errors.Wrap(err, "Failed reading certificate data")
	}

	reconcileAt, err := chain.Update(&m.options, &certificateChain)
	if err != nil {
		return 0, errors.Wrap(err, "Failed updating certificate data")
	}

	err = m.writeCertificateChain(objects, &certificateChain)
	if err != nil {
		return 0, errors.Wrap(err, "Failed writing certificate data")
	}

	logger.Info("Webhook certificates reconciled succesfuly")
	return reconcileAt.Sub(triple.Now()), nil
}

// VerifyTLS verifies that a certificate chain exists and is valid for the
// webhook configurations provided to this manager.
func (m *Manager) VerifyTLS() error {
	logger := m.log.WithName("VerifyTLS")
	m.active.Lock()
	m.verifying = true
	defer func() {
		m.verifying = false
		m.active.Unlock()
	}()

	logger.Info("Verifying webhook certificates")

	objects := objectMap{}
	certificateChain := chain.CertificateChainData{}

	err := m.readCertificateChain(objects, &certificateChain)
	if err != nil {
		return errors.Wrap(err, "Failed reading certificate data")
	}

	err = chain.Verify(&m.options, &certificateChain)
	if err != nil {
		return errors.Wrap(err, "Failed verifying certificate data")
	}

	logger.Info("Webhook certificates verified succesfully")
	return nil
}
