package server

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate"
	"github.com/qinqon/kube-admission-webhook/pkg/certificate/chain"
)

type Server struct {
	webhookServer  *webhook.Server
	webhookConfigs []certificate.WebhookReference
	newCertManager func() (*certificate.Manager, error)
	certManager    *certificate.Manager
	log            logr.Logger
}

type ServerModifier func(s *Server)

// Add creates a new Conditions Mutating Webhook and adds it to the Manager. The Manager will set fields on the Webhook
// and Start it when the Manager is Started.
func New(name, namespace string, client client.Client, options chain.Options, serverOpts ...ServerModifier) (*Server, error) {
	s := &Server{
		webhookServer: &webhook.Server{
			Port:    8443,
			CertDir: "/etc/webhook/certs/",
		},
		webhookConfigs: []certificate.WebhookReference{},
		log:            logf.Log.WithName("webhook/server"),
	}
	s.UpdateOpts(serverOpts...)
	s.webhookServer.Register("/readyz", healthz.CheckHandler{Checker: healthz.Ping})
	s.newCertManager = func() (*certificate.Manager, error) {
		return certificate.NewManager(name, namespace, client, options, s.webhookConfigs)
	}

	return s, nil
}

func WithHook(path string, hook *webhook.Admission) ServerModifier {
	return func(s *Server) {
		s.webhookServer.Register(path, hook)
	}
}

func WithPort(port int) ServerModifier {
	return func(s *Server) {
		s.webhookServer.Port = port
	}
}

func WithCertDir(certDir string) ServerModifier {
	return func(s *Server) {
		s.webhookServer.CertDir = certDir
	}
}

func WithConfig(webhookConfig certificate.WebhookReference) ServerModifier {
	return func(s *Server) {
		s.webhookConfigs = append(s.webhookConfigs, webhookConfig)
	}
}

//updates Server parameters using ServerModifier functions. Once the manager is started these parameters cannot be updated
func (s *Server) UpdateOpts(serverOpts ...ServerModifier) {
	for _, serverOpt := range serverOpts {
		serverOpt(s)
	}
}

func (s *Server) Add(mgr manager.Manager) error {
	var err error
	s.certManager, err = s.newCertManager()
	if err != nil {
		return errors.Wrap(err, "failed constructing certificate manager")
	}
	err = s.certManager.Add(mgr)
	if err != nil {
		return errors.Wrap(err, "failed adding certificate manager to controller-runtime manager")
	}
	err = mgr.Add(s)
	if err != nil {
		return errors.Wrap(err, "failed adding webhook server to controller-runtime manager")
	}
	return nil
}

func (s *Server) checkTLS() error {
	if s.certManager == nil {
		return errors.New("No manager has been added yet")
	}

	return s.certManager.VerifyTLS()
}

func (s *Server) waitForTLSReadiness() error {
	return wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		err := s.checkTLS()
		if err != nil {
			utilruntime.HandleError(err)
			return false, nil
		}
		return true, nil
	})
}

func (s *Server) Start(ctx context.Context) error {
	s.log.Info("Starting nodenetworkconfigurationpolicy webhook server")

	err := s.waitForTLSReadiness()
	if err != nil {
		return errors.Wrap(err, "failed watting for ready TLS key/cert")
	}

	err = s.webhookServer.Start(ctx)
	if err != nil {
		return errors.Wrap(err, "failed starting webhook server")
	}
	return nil
}

func (s *Server) InjectFunc(f inject.Func) error {
	return s.webhookServer.InjectFunc(f)
}

func (s *Server) NeedLeaderElection() bool {
	return s.webhookServer.NeedLeaderElection()
}
