package certificate

import (
	"context"
	"fmt"
	"reflect"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/chain"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CACertKey       = "ca.crt"
	CAPrivateKeyKey = "ca.key"

	secretManagedAnnotationKey = "kubevirt.io/kube-admission-webhook"

	clusterDomain    = ".cluster.local"
	serviceSubdomain = ".svc"
)

// configuration.go reads & writes certificate chain data from and to K8s
// resources related to the managed webhooks. This includes CA bundles on
// webhook resources, secrets for every backing service by the same name
// where service key pairs are stored, as well as a secret for the CA key
// pair by the name and namespace the manager operates under.

// objectKind is an internal string representation of K8s resource kinds
type objectKind string

const (
	mutatingWebhookType   objectKind = objectKind(MutatingWebhook)
	validatingWebhookType objectKind = objectKind(ValidatingWebhook)
	secretType            objectKind = "Secret"
)

// objectKey uniquely identifies a K8s resource
type objectKey struct {
	Kind objectKind
	types.NamespacedName
}

func (k objectKey) String() string {
	return fmt.Sprintf("%s/%s", k.Kind, k.NamespacedName.String())
}

// keyedObject references a K8s resource object by key
type keyedObject struct {
	key     *objectKey
	kobject client.Object
}
type objectMap map[*objectKey]*keyedObject

// objectOperators defines functors for initializing and mapping k8s resources
// to/from certificate chain data
type objectOperators struct {
	creator         func(name, namespace string) client.Object
	toChainMapper   func(*keyedObject, objectMap, *chain.CertificateChainData)
	fromChainMapper func(*keyedObject, *chain.CertificateChainData)
}

var (
	objectOperatorsMap = map[objectKind]objectOperators{
		mutatingWebhookType: {
			creator:         initMutatingWebhook,
			toChainMapper:   mapWebhookToChain,
			fromChainMapper: mapWebhookFromChain,
		},
		validatingWebhookType: {
			creator:         initValidatingWebhook,
			toChainMapper:   mapWebhookToChain,
			fromChainMapper: mapWebhookFromChain,
		},
		secretType: {
			creator:         initSecret,
			toChainMapper:   mapSecretToChain,
			fromChainMapper: mapSecretFromChain,
		},
	}
)

// readCertificateChain is the entry point to read from K8s all the certificate
// chain data related to the managed webhooks. This information is both tracked
// as a K8s object map and a certificate chain specific structure which should
// be supplied to this method initialized and empty.
func (m *Manager) readCertificateChain(objects objectMap, certificateChain *chain.CertificateChainData) error {
	m.initObjects(objects)
	certificateChain.CA.Name = m.secretCAName().String()
	err := m.readObjectsToChain(objects, certificateChain)
	return err
}

// writeCertificateChain is the entry point to write certificate chain data to K8s.
// objects & certificateChain should have been previously initialized with
// readCertificateChain. certificateChain could have had further in place
// modifications that this method would write back to object map and push to K8s.
func (m *Manager) writeCertificateChain(objects objectMap, certificateChain *chain.CertificateChainData) error {
	err := m.writeObjectsFromChain(objects, certificateChain)
	return err
}

// initObjects adds references of CA secret & managed webhooks to the object map
func (m *Manager) initObjects(objects objectMap) {
	for i := range m.webhooks {
		key := newObjectKey(objectKind(m.webhooks[i].Type), "", m.webhooks[i].Name)
		object := keyedObject{key, nil}
		objects[key] = &object
	}
	caSecretName := m.secretCAName()
	caSecretKey := newObjectKey(secretType, caSecretName.Namespace, caSecretName.Name)
	caSecretObject := keyedObject{caSecretKey, nil}
	objects[caSecretKey] = &caSecretObject
}

// readObjectsToChain reads objects referenced in the object map from storage
// and maps them to certificate chain data. Further object references can be
// added to the object map as object are read. Thus this method will loop
// though the objet map until all objects are read.
func (m *Manager) readObjectsToChain(objects objectMap, certificateChain *chain.CertificateChainData) error {
	for {
		var objectRead bool
		for _, object := range objects {
			if object.kobject == nil {
				objectRead = true
				err := m.readObjectToChain(object, objects, certificateChain)
				if err != nil {
					return err
				}
			}
		}
		if !objectRead {
			return nil
		}
	}
}

// writeObjectsFromChain maps certificate chain data back to the object map and
// pushed data to K8s.
func (m *Manager) writeObjectsFromChain(objects objectMap, certificateChain *chain.CertificateChainData) error {
	for _, object := range objects {
		err := m.writeObjectFromChain(object, certificateChain)
		if err != nil {
			return err
		}
	}
	return nil
}

// readObjectToChain initializes, reads & maps an object from K8s as defined by
// create & map operators in objectOperatorsMap for every kind of object.
// Operators may add further object references to the object map to be read. An
// Object may not exist in K8s and is reponsibility of the map operator to detect
// and act on this circumstance, where removing the reference to the object from the
// map is ap possibility.
func (m *Manager) readObjectToChain(object *keyedObject, objects objectMap, certificateChain *chain.CertificateChainData) error {
	logger := m.log.WithName("readObjectToChain").WithValues("key", object.key)
	if object.kobject != nil {
		return nil
	}

	objectOps := objectOperatorsMap[object.key.Kind]
	object.kobject = objectOps.creator(object.key.Name, object.key.Namespace)

	logger.Info("Read object")
	err := m.get(object.key.NamespacedName, object.kobject)
	notFound := apierrors.IsNotFound(err)
	if err != nil && (!notFound || m.verifying) {
		return err
	}

	objectOps.toChainMapper(object, objects, certificateChain)
	return nil
}

// writeObjectFromChain maps & writes and object to K8s from certificate chain
// data. The operation will fail if the object changed since originally read
// and will be noop if no changes need to be written to the object.
func (m *Manager) writeObjectFromChain(object *keyedObject, certificateChain *chain.CertificateChainData) error {
	logger := m.log.WithName("writeObjectFromChain").WithValues("key", object.key)

	old := object.kobject.DeepCopyObject()
	err := m.get(object.key.NamespacedName, object.kobject)
	new := apierrors.IsNotFound(err)
	current := object.kobject.DeepCopyObject()
	if err != nil && !new {
		return err
	}

	objectOps := objectOperatorsMap[object.key.Kind]
	objectOps.fromChainMapper(object, certificateChain)

	if reflect.DeepEqual(old, object.kobject) {
		// noop
		return nil
	}

	if !reflect.DeepEqual(old, current) {
		return fmt.Errorf("An object changed since originally read: %s", object.key)
	}

	if new {
		logger.Info("Create object")
		err = m.client.Create(context.TODO(), object.kobject)
	} else {
		logger.Info("Update object")
		err = m.client.Update(context.TODO(), object.kobject)
	}

	return err
}

func initMutatingWebhook(name, namespace string) client.Object {
	return &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func initValidatingWebhook(name, namespace string) client.Object {
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func initSecret(name, namespace string) client.Object {
	return &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				secretManagedAnnotationKey: "",
			},
		},
	}
}

// mapWebhookToChain maps a webhook object to certificate chain data.
// If the webhook has no relevant data or does not exist, it is removed
// from the object map so that is no longer considered. For every backing
// service of the webhook, a reference to the service secret is added to the
// object map if not already there.
func mapWebhookToChain(object *keyedObject, objects objectMap, certificateChain *chain.CertificateChainData) {
	clientConfigMap := clientConfigMap(object.kobject)
	if len(clientConfigMap) <= 0 {
		delete(objects, object.key)
		return
	}

	if certificateChain.CertificatesIssued == nil {
		certificateChain.CertificatesIssued = map[string]*chain.CertificateIssue{}
	}

	for name, config := range clientConfigMap {
		serviceName := config.Service.Name
		serviceNamespace := config.Service.Namespace
		serviceHostname := serviceHostname(serviceName, serviceNamespace)

		if _, found := certificateChain.CertificatesIssued[serviceHostname]; !found {
			certificateChain.CertificatesIssued[serviceHostname] = newCertificateIssue(serviceName, serviceNamespace)
		}

		caBundleName := caBundleName(object.key.String(), name)
		certificateChain.CertificatesIssued[serviceHostname].CACertPEM[caBundleName] = config.CABundle
		key := newObjectKey("Secret", serviceNamespace, serviceName)
		if _, found := objects[key]; !found {
			objects[key] = &keyedObject{key, nil}
		}
	}
}

// mapWebhookToChain maps a webhook object from certificate chain data.
func mapWebhookFromChain(object *keyedObject, certificateChain *chain.CertificateChainData) {
	clientConfigList := clientConfigMap(object.kobject)
	for name, config := range clientConfigList {
		serviceHostname := serviceHostname(config.Service.Name, config.Service.Namespace)
		certificateIssue := certificateChain.CertificatesIssued[serviceHostname]
		if certificateIssue == nil {
			continue
		}
		caBundleName := caBundleName(object.key.String(), name)
		caBundle := certificateIssue.CACertPEM[caBundleName]
		if caBundle == nil {
			continue
		}
		config.CABundle = caBundle
	}
}

// mapWebhookToChain maps a secret object to certificate chain data.
func mapSecretToChain(object *keyedObject, objects objectMap, certificateChain *chain.CertificateChainData) {
	if object.key.NamespacedName.String() == certificateChain.CA.Name {
		mapCASecretToChain(object, certificateChain)
		return
	}
	mapServiceSecretToChain(object, certificateChain)
}

// mapWebhookToChain maps a secret object from certificate chain data.
func mapSecretFromChain(object *keyedObject, certificateChain *chain.CertificateChainData) {
	if object.key.NamespacedName.String() == certificateChain.CA.Name {
		mapCASecretFromChain(object, certificateChain)
		return
	}
	mapServiceSecretFromChain(object, certificateChain)
}

func mapServiceSecretToChain(object *keyedObject, certificateChain *chain.CertificateChainData) {
	secret := object.kobject.(*corev1.Secret)
	key := secret.Data[corev1.TLSPrivateKeyKey]
	cert := secret.Data[corev1.TLSCertKey]
	if key == nil || cert == nil {
		return
	}

	name := serviceHostname(object.key.NamespacedName.Name, object.key.NamespacedName.Namespace)

	certificateChain.CertificatesIssued[name].KeyPEM = key
	certificateChain.CertificatesIssued[name].CertPEM = cert
}

func mapCASecretToChain(object *keyedObject, certificateChain *chain.CertificateChainData) {
	secret := object.kobject.(*corev1.Secret)
	key := secret.Data[CAPrivateKeyKey]
	cert := secret.Data[CACertKey]
	if key == nil || cert == nil {
		return
	}
	certificateChain.CA.KeyPEM = key
	certificateChain.CA.CertPEM = cert
}

func mapServiceSecretFromChain(object *keyedObject, certificateChain *chain.CertificateChainData) {
	secret := object.kobject.(*corev1.Secret)
	name := serviceHostname(object.key.NamespacedName.Name, object.key.NamespacedName.Namespace)
	bundle := certificateChain.CertificatesIssued[name]
	if bundle == nil {
		return
	}
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Type = corev1.SecretTypeTLS
	secret.Data[corev1.TLSPrivateKeyKey] = bundle.KeyPEM
	secret.Data[corev1.TLSCertKey] = bundle.CertPEM
}

func mapCASecretFromChain(object *keyedObject, certificateChain *chain.CertificateChainData) {
	secret := object.kobject.(*corev1.Secret)
	secret.Type = corev1.SecretTypeOpaque
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[CAPrivateKeyKey] = certificateChain.CA.KeyPEM
	secret.Data[CACertKey] = certificateChain.CA.CertPEM
}

func newObjectKey(kind objectKind, namespace, name string) *objectKey {
	key := objectKey{
		Kind: kind,
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	return &key
}

func (m *Manager) secretCAName() types.NamespacedName {
	return types.NamespacedName{m.namespace, m.name + "-ca"}
}

func caBundleName(webhookName, configName string) string {
	return webhookName + "-" + configName
}

func namespacedHostname(name, namespace string) string {
	return name + "." + namespace
}

func serviceHostname(name, namespace string) string {
	return name + "." + namespace + serviceSubdomain
}

func serviceFqdn(name, namespace string) string {
	return name + "." + namespace + serviceSubdomain + clusterDomain
}

func newCertificateIssue(name, namespace string) *chain.CertificateIssue {
	commonName := serviceHostname(name, namespace)
	hostnames := []string{
		name,
		namespacedHostname(name, namespace),
		commonName,
		serviceFqdn(name, namespace),
	}
	certificateBundle := chain.CertificateIssue{
		Name:      commonName,
		Hostnames: hostnames,
		CACertPEM: make(map[string][]byte),
	}
	return &certificateBundle
}

func mutatingWebhookConfig(webhook client.Object) *admissionregistrationv1.MutatingWebhookConfiguration {
	return webhook.(*admissionregistrationv1.MutatingWebhookConfiguration)
}

func validatingWebhookConfig(webhook client.Object) *admissionregistrationv1.ValidatingWebhookConfiguration {
	return webhook.(*admissionregistrationv1.ValidatingWebhookConfiguration)
}

// clientConfigMap returns the the list of webhooks's mutation or validating WebhookClientConfig
//
// The WebhookClientConfig type is share between mutating or validating so we can have a common function
// that uses the interface runtime.Object and do some type checking to access it [1].
//
// [1] https://godoc.org/k8s.io/kubernetes/pkg/apis/admissionregistration#WebhookClientConfig
func clientConfigMap(webhook client.Object) map[string]*admissionregistrationv1.WebhookClientConfig {
	clientConfigMap := map[string]*admissionregistrationv1.WebhookClientConfig{}
	switch webhook.(type) {
	case *admissionregistrationv1.MutatingWebhookConfiguration:
		mutatingWebhookConfig := mutatingWebhookConfig(webhook)
		for i := range mutatingWebhookConfig.Webhooks {
			name := mutatingWebhookConfig.Webhooks[i].Name
			clientConfig := &mutatingWebhookConfig.Webhooks[i].ClientConfig
			if clientConfig.Service == nil {
				continue
			}
			clientConfigMap[name] = clientConfig
		}
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		validatingWebhookConfig := validatingWebhookConfig(webhook)
		for i := range validatingWebhookConfig.Webhooks {
			name := validatingWebhookConfig.Webhooks[i].Name
			clientConfig := &validatingWebhookConfig.Webhooks[i].ClientConfig
			if clientConfig.Service == nil {
				continue
			}
			clientConfigMap[name] = clientConfig
		}
	}
	return clientConfigMap
}
