# kube-admission-webhook
k8s admission webhook library with certificate rotation and caBundle update.

## CA/Service certificate/key generation
The library generates at RSA key with 2048 size both for CA and server and
certificate the share the expiration time so all the CA and service certificates
are rotated at onces just before expiration time.

## Webhook service
It has a one year expiration time harcoded and apart from wrapping the
controller runtime webhook library it waits for TLS key/cert existence and
correctness before sarting the service this wait cert-manager runs in parallel
wait webhook just wait for proper TLS infra to be there.

## Cert manager
It's implemented as a controller runtime `Runnable` to be plug into the manager
to re-use controller-runtime lifecycle code. The cert manager instance
has to be unique per cluster so either is running a a `Deployment` with proper
replication or use Leader Election at controller-runtime logic, if this is the
case in case the other controllers need to be non leader election a drop in
place controller has beeing added to this project.

## Examples
There is a integration example under test/pod it contains two controllers and
a webhook, one of the controllers uses leader election there other do not so
all the bits from this project are represented.
