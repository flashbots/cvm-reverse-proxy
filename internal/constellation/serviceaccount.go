/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package constellation

import (
	"fmt"

	"cvm-reverse-proxy/internal/cloud/azureshared"
	"cvm-reverse-proxy/internal/cloud/cloudprovider"
	"cvm-reverse-proxy/internal/cloud/gcpshared"
	"cvm-reverse-proxy/internal/cloud/openstack"
)

// MarshalServiceAccountURI returns the service account URI for the given cloud provider.
func MarshalServiceAccountURI(provider cloudprovider.Provider, payload ServiceAccountPayload) (string, error) {
	switch provider {
	case cloudprovider.GCP:
		return payload.GCP.ToCloudServiceAccountURI(), nil

	case cloudprovider.AWS:
		return "", nil // AWS does not need a service account URI

	case cloudprovider.Azure:
		return payload.Azure.ToCloudServiceAccountURI(), nil

	case cloudprovider.OpenStack:
		return payload.OpenStack.ToCloudServiceAccountURI(), nil

	case cloudprovider.QEMU:
		return "", nil // QEMU does not use service account keys

	default:
		return "", fmt.Errorf("unsupported cloud provider %q", provider)
	}
}

// ServiceAccountPayload is data a service account URI can be built
// from for a given cloud provider.
type ServiceAccountPayload struct {
	GCP       gcpshared.ServiceAccountKey
	Azure     azureshared.ApplicationCredentials
	OpenStack openstack.AccountKey
}
