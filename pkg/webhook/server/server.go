package server

import (
	"github.com/go-logr/logr"
	"github.com/pkg/errors"

	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	certificate "github.com/qinqon/kube-admission-webhook/pkg/webhook/server/certificate"
)

type Server struct {
	mgr           manager.Manager
	webhookName   string
	webhookType   certificate.WebhookType
	webhookServer *webhook.Server
	caCertPath    string
	log           logr.Logger
}

type ServerModifier func(w *Server)

// Add creates a new Conditions Mutating Webhook and adds it to the Manager. The Manager will set fields on the Webhook
// and Start it when the Manager is Started.
func New(mgr manager.Manager, webhookName string, webhookType certificate.WebhookType, serverOpts ...ServerModifier) *Server {
	s := &Server{
		webhookName: webhookName,
		webhookType: webhookType,
		webhookServer: &webhook.Server{
			Port:    8443,
			CertDir: "/etc/webhook/certs/",
		},
		caCertPath: "/etc/webhook/ca/client-ca-file",
		mgr:        mgr,
		log:        logf.Log.WithName("webhook/server"),
	}
	s.updateServerOpts(serverOpts...)

	return s
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

func WithCaCertPath(caCertPath string) ServerModifier {
	return func(s *Server) {
		s.caCertPath = caCertPath
	}
}

//updates Server parameters using ServerModifier functions. Once the manager is started these parameters cannot be updated
func (s *Server) updateServerOpts(serverOpts ...ServerModifier) {
	for _, serverOpt := range serverOpts {
		serverOpt(s)
	}
}

func (s *Server) Start(stop <-chan struct{}) error {
	s.log.Info("Starting nodenetworkconfigurationpolicy webhook server")

	certManager, err := certificate.NewManager(s.mgr, s.webhookName, s.webhookType, s.webhookServer.CertDir, "tls.crt", "tls.key", s.caCertPath)
	if err != nil {
		return errors.Wrap(err, "failed creating new webhook cert manager")
	}

	err = certManager.Start()
	if err != nil {
		return errors.Wrap(err, "failed starting webhook cert manager")
	}
	defer certManager.Stop()

	err = s.webhookServer.Start(stop)
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
