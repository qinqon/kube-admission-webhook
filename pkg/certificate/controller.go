package certificate

import (
	"context"

	"github.com/pkg/errors"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Add creates a new Node Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func (m *Manager) Add(mgr manager.Manager) error {
	return m.add(mgr, m)
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func (m *Manager) add(mgr manager.Manager, r reconcile.Reconciler) error {
	logger := m.log.WithName("add")
	// Create a new controller
	c, err := controller.New("certificate-controller", mgr, controller.Options{Reconciler: m})
	if err != nil {
		return errors.Wrap(err, "failed instanciating certificate controller")
	}

	isAnnotatedResource := func(object client.Object) bool {
		_, foundAnnotation := object.GetAnnotations()[secretManagedAnnotationKey]
		return foundAnnotation
	}

	isWebhookConfig := func(object client.Object) bool {
		var webhookType WebhookType
		switch object.(type) {
		case *admissionregistrationv1.MutatingWebhookConfiguration:
			webhookType = MutatingWebhook
		case *admissionregistrationv1.ValidatingWebhookConfiguration:
			webhookType = ValidatingWebhook
		default:
			return false
		}
		for _, webhookRef := range m.webhooks {
			if webhookRef.Name == object.GetName() && webhookRef.Type == webhookType {
				return true
			}
		}
		return false
	}

	// Watch only events for selected m.webhookName
	onEventForThisWebhook := predicate.Funcs{
		CreateFunc: func(createEvent event.CreateEvent) bool {
			return isWebhookConfig(createEvent.Object) || isAnnotatedResource(createEvent.Object)
		},
		DeleteFunc: func(deleteEvent event.DeleteEvent) bool {
			return isAnnotatedResource(deleteEvent.Object)
		},
		UpdateFunc: func(updateEvent event.UpdateEvent) bool {
			return isWebhookConfig(updateEvent.ObjectOld) || isAnnotatedResource(updateEvent.ObjectOld)
		},
		GenericFunc: func(genericEvent event.GenericEvent) bool {
			return isWebhookConfig(genericEvent.Object) || isAnnotatedResource(genericEvent.Object)
		},
	}

	logger.Info("Starting to watch secrets")
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, onEventForThisWebhook)
	if err != nil {
		return errors.Wrap(err, "failed watching Secret")
	}

	logger.Info("Starting to watch validatingwebhookconfiguration")
	err = c.Watch(&source.Kind{Type: &admissionregistrationv1.ValidatingWebhookConfiguration{}}, &handler.EnqueueRequestForObject{}, onEventForThisWebhook)
	if err != nil {
		return errors.Wrap(err, "failed watching ValidatingWebhookConfiguration")
	}

	logger.Info("Starting to watch mutatingwebhookconfiguration")
	err = c.Watch(&source.Kind{Type: &admissionregistrationv1.MutatingWebhookConfiguration{}}, &handler.EnqueueRequestForObject{}, onEventForThisWebhook)
	if err != nil {
		return errors.Wrap(err, "failed watching MutatingWebhookConfiguration")
	}

	return nil
}

func (m *Manager) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logger := m.log.WithName("Reconcile")
	logger.Info("Incoming reconcile request", "Request.Namespace", request.Namespace, "Request.Name", request.Name)

	requeueAfter, err := m.reconcileCertificates()
	if err != nil {
		logger.Error(err, "Reconcile failed, inmediate requeue")
		return reconcile.Result{}, err
	}

	logger.Info("Reconcile done, requeuing", "RequeueAfter", requeueAfter)
	return reconcile.Result{Requeue: true, RequeueAfter: requeueAfter}, nil
}
