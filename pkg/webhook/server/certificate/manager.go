package certificate

import (
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	"github.com/qinqon/kube-admission-webhook/pkg/webhook/server/certificate/triple"
)

type manager struct {
	client           client.Client
	webhookName      string
	webhookType      WebhookType
	keyPairByService map[types.NamespacedName]*triple.KeyPair
	caKeyPair        *triple.KeyPair
	now              func() time.Time
	stopCh           chan struct{}
	log              logr.Logger
	ready            bool
}

type WebhookType string

const (
	MutatingWebhook   WebhookType = "Mutating"
	ValidatingWebhook WebhookType = "Validating"
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
) *manager {

	m := &manager{
		stopCh:           make(chan struct{}),
		client:           client,
		webhookName:      webhookName,
		webhookType:      webhookType,
		keyPairByService: map[types.NamespacedName]*triple.KeyPair{},
		now:              time.Now,
		ready:            false,
		log: logf.Log.WithName("webhook/server/certificate/manager").
			WithValues("webhookType", webhookType, "webhookName", webhookName),
	}
	return m
}

// Will start the the underlaying client-go cert manager [1]  and
// wait for TLS key and cert to be generated
//
// [1] https://godoc.org/k8s.io/client-go/util/certificate
func (m *manager) Start() error {
	m.log.Info("Starting cert manager")

	go wait.Until(func() {
		deadline := m.nextRotationDeadline()
		if sleepInterval := deadline.Sub(m.now()); sleepInterval > 0 {
			m.log.Info(fmt.Sprintf("Waiting %v for next certificate rotation", sleepInterval))

			timer := time.NewTimer(sleepInterval)
			defer timer.Stop()

			select {
			case <-timer.C:
			}
		}

		backoff := wait.Backoff{
			Duration: 2 * time.Second,
			Factor:   2,
			Jitter:   0.1,
			Steps:    5,
		}
		if err := wait.ExponentialBackoff(backoff, m.rotateCondition); err != nil {
			utilruntime.HandleError(fmt.Errorf("Reached backoff limit, still unable to rotate certs: %v", err))
			wait.PollInfinite(32*time.Second, m.rotateCondition)
		}
	}, time.Second, m.stopCh)

	return nil
}

func (m *manager) rotateCondition() (bool, error) {
	err := m.rotate()
	if err != nil {
		utilruntime.HandleError(err)
		return false, nil
	}
	return true, nil
}

func (m *manager) rotate() error {

	m.ready = false

	m.log.Info("Rotating TLS cert/key")

	oneYearDuration := 365 * 24 * time.Hour

	caKeyPair, err := triple.NewCA(m.webhookName, oneYearDuration)
	if err != nil {
		return errors.Wrap(err, "failed generating CA cert/key")
	}

	m.caKeyPair = caKeyPair

	err = m.updateWebhookCABundle()
	if err != nil {
		return errors.Wrap(err, "failed to update CA bundle at webhook")
	}

	webhookConf, err := m.webhookConfiguration()
	if err != nil {
		return errors.Wrap(err, "failed to reading configuration")
	}

	for _, clientConfig := range m.clientConfigList(webhookConf) {
		service := types.NamespacedName{Name: clientConfig.Service.Name, Namespace: clientConfig.Service.Namespace}
		keyPair, err := triple.NewServerKeyPair(
			caKeyPair,
			service.Name+"."+service.Namespace+".pod.cluster.local",
			service.Name,
			service.Namespace,
			"cluster.local",
			nil,
			nil,
			oneYearDuration,
		)
		if err != nil {
			return errors.Wrapf(err, "failed creating server key/cert for service %+v", service)
		}
		m.createOrUpdateTLSSecret(service, keyPair)
	}

	m.ready = true

	return nil
}

// nextRotationDeadline returns a value for the threshold at which the
// current certificate should be rotated, 80%+/-10% of the expiration of the
// certificate.
func (m *manager) nextRotationDeadline() time.Time {
	if m.caKeyPair == nil {
		m.log.Info("Certificates not created, forcing roration")
		return m.now()
	}
	notAfter := m.caKeyPair.Cert.NotAfter
	totalDuration := float64(notAfter.Sub(m.caKeyPair.Cert.NotBefore))
	deadline := m.caKeyPair.Cert.NotBefore.Add(jitteryDuration(totalDuration))

	m.log.Info(fmt.Sprintf("Certificate expiration is %v, rotation deadline is %v", notAfter, deadline))
	return deadline
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

func (m *manager) Stop() {
	m.log.Info("Stopping cert manager")
	close(m.stopCh)
}

func (m *manager) WaitForReadiness() error {
	return wait.PollImmediate(5*time.Second, 20*time.Second, func() (bool, error) {
		return m.ready, nil
	})
}
