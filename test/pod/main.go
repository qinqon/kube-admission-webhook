package main

import (
	"os"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate"
	"github.com/qinqon/kube-admission-webhook/pkg/controller"
	webhookserver "github.com/qinqon/kube-admission-webhook/pkg/webhook/server"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
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
	entryLog.Info("Setting up controller without leader election")
	controllerWithoutLeaderElection, err := controller.New("foo-controller-without-leader-election", mgr, controller.Options{
		WithoutLeaderElection: true,
		Reconciler:            &reconcileReplicaSet{client: mgr.GetClient(), log: log.WithName("reconciler")},
	})
	if err != nil {
		entryLog.Error(err, "unable to set up individual controller")
		os.Exit(1)
	}

	// Setup a new controller to reconcile ReplicaSets
	entryLog.Info("Setting up controller with leader election")
	controllerWithLeaderElection, err := controller.New("foo-controller-with-leader-election", mgr, controller.Options{
		WithoutLeaderElection: false,
		Reconciler:            &reconcileReplicaSet{client: mgr.GetClient(), log: log.WithName("reconciler")},
	})
	if err != nil {
		entryLog.Error(err, "unable to set up individual controller")
		os.Exit(1)
	}

	// Watch ReplicaSets and enqueue ReplicaSet object key
	if err := controllerWithoutLeaderElection.Watch(&source.Kind{Type: &appsv1.ReplicaSet{}}, &handler.EnqueueRequestForObject{}); err != nil {
		entryLog.Error(err, "unable to watch ReplicaSets")
		os.Exit(1)
	}

	// Watch Pods and enqueue owning ReplicaSet key
	if err := controllerWithLeaderElection.Watch(&source.Kind{Type: &corev1.Pod{}},
		&handler.EnqueueRequestForOwner{OwnerType: &appsv1.ReplicaSet{}, IsController: true}); err != nil {
		entryLog.Error(err, "unable to watch Pods")
		os.Exit(1)
	}

	// Setup webhooks
	entryLog.Info("setting up webhook server")
	mutatingWebhookServer, err := webhookserver.New(mgr.GetClient(), certificate.Options{WebhookName: "test-webhook", WebhookType: certificate.MutatingWebhook, Namespace: "mynamespace", CARotateInterval: certificate.OneYearDuration, CertRotateInterval: certificate.OneYearDuration})
	if err != nil {
		os.Exit(1)
	}

	validatingWebhookServer, err := webhookserver.New(mgr.GetClient(), certificate.Options{WebhookName: "test-webhook", WebhookType: certificate.ValidatingWebhook, Namespace: "mynamespace", CARotateInterval: certificate.OneYearDuration, CertRotateInterval: certificate.OneYearDuration})
	if err != nil {
		os.Exit(1)
	}

	entryLog.Info("registering webhooks to the webhook server")
	mutatingWebhookServer.UpdateOpts(webhookserver.WithHook("/mutate-v1-pod", &webhook.Admission{Handler: &podAnnotator{Client: mgr.GetClient()}}))
	validatingWebhookServer.UpdateOpts(webhookserver.WithHook("/validate-v1-pod", &webhook.Admission{Handler: &podValidator{Client: mgr.GetClient()}}))

	entryLog.Info("starting manager")
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		entryLog.Error(err, "unable to run manager")
		os.Exit(1)
	}
}
