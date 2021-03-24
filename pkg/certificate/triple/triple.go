/*
Copyright 2016 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package triple generates key-certificate pairs for the
// triple (CA, Server, Client).
package triple

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type KeyPair struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

func NewCA(name string, duration time.Duration) (*KeyPair, error) {
	key, err := NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to create a private key for a new CA: %v", err)
	}

	config := Config{
		CommonName: name,
	}

	cert, err := NewSelfSignedCACert(config, key, duration)
	if err != nil {
		return nil, fmt.Errorf("unable to create a self-signed certificate for a new CA: %v", err)
	}
	return &KeyPair{
		Key:  key,
		Cert: cert,
	}, nil
}

func NewServerKeyPair(ca *KeyPair, commonName string, ips, hostnames []string, duration time.Duration) (*KeyPair, error) {
	key, err := NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to create a server private key: %v", err)
	}

	altNames := AltNames{}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			altNames.IPs = append(altNames.IPs, ip)
		}
	}
	altNames.DNSNames = append(altNames.DNSNames, hostnames...)

	config := Config{
		CommonName: commonName,
		AltNames:   altNames,
		Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, err := NewSignedCert(config, key, ca.Cert, ca.Key, duration)
	if err != nil {
		return nil, fmt.Errorf("unable to sign the server certificate: %v", err)
	}

	return &KeyPair{
		Key:  key,
		Cert: cert,
	}, nil
}

func NewClientKeyPair(ca *KeyPair, commonName string, organizations []string, duration time.Duration) (*KeyPair, error) {
	key, err := NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to create a client private key: %v", err)
	}

	config := Config{
		CommonName:   commonName,
		Organization: organizations,
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, err := NewSignedCert(config, key, ca.Cert, ca.Key, duration)
	if err != nil {
		return nil, fmt.Errorf("unable to sign the client certificate: %v", err)
	}

	return &KeyPair{
		Key:  key,
		Cert: cert,
	}, nil
}
