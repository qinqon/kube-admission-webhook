package main

import (
	"os"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate"
	webhookserver "github.com/qinqon/kube-admission-webhook/pkg/webhook/server"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
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

	// Setup a new controller to reconcile ReplicaSets
	entryLog.Info("Setting up controller")
	podController, err := controller.New("pod-controller", mgr, controller.Options{
		Reconciler: &reconcileReplicaSet{client: mgr.GetClient(), log: log.WithName("reconciler")},
	})
	if err != nil {
		entryLog.Error(err, "unable to set up individual controller")
		os.Exit(1)
	}

	// Watch Pods and enqueue owning ReplicaSet key
	if err := podController.Watch(&source.Kind{Type: &corev1.Pod{}},
		&handler.EnqueueRequestForOwner{OwnerType: &appsv1.ReplicaSet{}, IsController: true}); err != nil {
		entryLog.Error(err, "unable to watch Pods")
		os.Exit(1)
	}

	// Setup webhooks
	entryLog.Info("setting up webhook server")
	mutatingWebhookServer := webhookserver.New(mgr.GetClient(), "test-webhook", certificate.MutatingWebhook, certificate.OneYearDuration)
	validatingWebhookServer := webhookserver.New(mgr.GetClient(), "test-webhook", certificate.ValidatingWebhook, certificate.OneYearDuration)

	entryLog.Info("registering webhooks to the webhook server")
	mutatingWebhookServer.UpdateOpts(webhookserver.WithHook("/mutate-v1-pod", &webhook.Admission{Handler: &podAnnotator{Client: mgr.GetClient()}}))
	validatingWebhookServer.UpdateOpts(webhookserver.WithHook("/validate-v1-pod", &webhook.Admission{Handler: &podValidator{Client: mgr.GetClient()}}))

	entryLog.Info("starting manager")
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		entryLog.Error(err, "unable to run manager")
		os.Exit(1)
	}
}
