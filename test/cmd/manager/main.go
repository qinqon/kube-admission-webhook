package main

import (
	"os"

	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	webhookserver "github.com/qinqon/kube-admission-webhook/pkg/webhook/server"
	"github.com/qinqon/kube-admission-webhook/pkg/webhook/server/certificate"
	"github.com/qinqon/kube-admission-webhook/test/pkg/example"
)

var log = logf.Log.WithName("example-controller")

func main() {
	logf.SetLogger(zap.Logger(false))
	entryLog := log.WithName("entrypoint")

	// Setup a Manager
	entryLog.Info("setting up manager")
	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
		LeaderElectionNamespace: "mynamespace",
		LeaderElectionID:        "foo-lock",
		LeaderElection:          true,
	})
	if err != nil {
		entryLog.Error(err, "unable to set up overall controller manager")
		os.Exit(1)
	}

	// Setup webhooks
	entryLog.Info("setting up webhook server")
	mutatingWebhookServer := webhookserver.New(mgr.GetClient(), "test-webhook", certificate.MutatingWebhook)
	validatingWebhookServer := webhookserver.New(mgr.GetClient(), "test-webhook", certificate.ValidatingWebhook)

	entryLog.Info("registering webhooks to the webhook server")
	mutatingWebhookServer.UpdateOpts(webhookserver.WithHook("/mutate-v1-pod", &webhook.Admission{Handler: &example.PodAnnotator{Client: mgr.GetClient()}}))
	validatingWebhookServer.UpdateOpts(webhookserver.WithHook("/validate-v1-pod", &webhook.Admission{Handler: &example.PodValidator{Client: mgr.GetClient()}}))

	entryLog.Info("starting manager")
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		entryLog.Error(err, "unable to run manager")
		os.Exit(1)
	}
}
