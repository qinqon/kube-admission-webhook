package chain

import (
	"github.com/pkg/errors"

	"github.com/qinqon/kube-admission-webhook/pkg/certificate/triple"
)

func (r *certificateChain) rotateAll() error {
	r.log.WithName("rotateAll").Info("Rotating CA key pair")

	duration := r.getCARotateInterval()
	caKeyPair, err := triple.NewCA(r.data.CA.Name, duration)
	if err != nil {
		return errors.Wrap(err, "Failed generating CA key pair")
	}

	r.setCaKeyPair(caKeyPair)

	// We have rotate the CA we need to reset the TLS removing previous certs
	err = r.rotateCertsWithoutOverlap()
	if err != nil {
		return errors.Wrap(err, "Failed rotating chains")
	}

	return nil
}

func (c *certificateChain) rotateCerts(applyFn func(*certificateChain, *CertificateIssue, *triple.KeyPair)) error {
	logger := c.log.WithName("rotateCerts")

	for _, certificateIssued := range c.data.CertificatesIssued {
		logger.Info("Rotating key pair for certificate", "name", certificateIssued.Name)
		duration := c.getCertRotateInterval()
		keyPair, err := triple.NewServerKeyPair(
			c.data.CA.keyPair,
			certificateIssued.Name,
			certificateIssued.IPs,
			certificateIssued.Hostnames,
			duration,
		)
		if err != nil {
			return errors.Wrapf(err, "Failed creating key pair for certificate %s", certificateIssued.Name)
		}
		applyFn(c, certificateIssued, keyPair)
	}

	return nil
}

func (r *certificateChain) rotateCertsWithoutOverlap() error {
	r.log.WithName("rotateCertsWithoutOverlap").Info("Rotating certificates without overlap")
	return r.rotateCerts((*certificateChain).setKeyResetCert)
}

func (r *certificateChain) rotateCertsWithOverlap() error {
	r.log.WithName("rotateBundlesWithOverlap").Info("Rotating certificates with overlap")
	return r.rotateCerts((*certificateChain).setKeyAppendCert)
}
