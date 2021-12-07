/*
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
package oracle

import (
	"context"
	"fmt"
	"github.com/external-secrets/external-secrets/pkg/serializer"
	"github.com/oracle/oci-go-sdk/v45/common"
	vault "github.com/oracle/oci-go-sdk/v45/vault"
	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	"github.com/external-secrets/external-secrets/pkg/provider"
	"github.com/external-secrets/external-secrets/pkg/provider/aws/util"
	"github.com/external-secrets/external-secrets/pkg/provider/schema"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

const (
	VaultEndpointEnv = "ORACLE_VAULT_ENDPOINT"
	STSEndpointEnv   = "ORACLE_STS_ENDPOINT"
	SVMEndpointEnv   = "ORACLE_SVM_ENDPOINT"

	errOracleClient                          = "cannot setup new oracle client: %w"
	errORACLECredSecretName                  = "invalid oracle SecretStore resource: missing oracle APIKey"
	errUninitalizedOracleProvider            = "provider oracle is not initialized"
	errInvalidClusterStoreMissingSKNamespace = "invalid ClusterStore, missing namespace"
	errFetchSAKSecret                        = "could not fetch SecretAccessKey secret: %w"
	errMissingPK                             = "missing PrivateKey"
	errMissingUser                           = "missing User ID"
	errMissingTenancy                        = "missing Tenancy ID"
	errMissingRegion                         = "missing Region"
	errMissingFingerprint                    = "missing Fingerprint"
	errMissingKey                            = "missing Key in secret: %s"
	errInvalidSecret                         = "invalid secret received. no secret string nor binary for key: %s"
)

type client struct {
	kube        kclient.Client
	store       *esv1alpha1.OracleProvider
	namespace   string
	storeKind   string
	tenancy     string
	user        string
	region      string
	fingerprint string
	privateKey  string
}

type VaultManagementService struct {
	Client VMInterface
}

type VMInterface interface {
	GetSecret(ctx context.Context, request vault.GetSecretRequest) (response vault.GetSecretResponse, err error)
}

func (c *client) setAuth(ctx context.Context) error {
	credentialsSecret := &corev1.Secret{}
	credentialsSecretName := c.store.Auth.SecretRef.PrivateKey.Name
	if credentialsSecretName == "" {
		return fmt.Errorf(errORACLECredSecretName)
	}
	objectKey := types.NamespacedName{
		Name:      credentialsSecretName,
		Namespace: c.namespace,
	}

	// only ClusterStore is allowed to set namespace (and then it's required)
	if c.storeKind == esv1alpha1.ClusterSecretStoreKind {
		if c.store.Auth.SecretRef.PrivateKey.Namespace == nil {
			return fmt.Errorf(errInvalidClusterStoreMissingSKNamespace)
		}
		objectKey.Namespace = *c.store.Auth.SecretRef.PrivateKey.Namespace
	}

	err := c.kube.Get(ctx, objectKey, credentialsSecret)
	if err != nil {
		return fmt.Errorf(errFetchSAKSecret, err)
	}

	c.privateKey = string(credentialsSecret.Data[c.store.Auth.SecretRef.PrivateKey.Key])
	if c.privateKey == "" {
		return fmt.Errorf(errMissingPK)
	}

	c.fingerprint = string(credentialsSecret.Data[c.store.Auth.SecretRef.Fingerprint.Key])
	if c.fingerprint == "" {
		return fmt.Errorf(errMissingFingerprint)
	}

	c.user = c.store.User
	if c.user == "" {
		return fmt.Errorf(errMissingUser)
	}

	c.tenancy = c.store.Tenancy
	if c.tenancy == "" {
		return fmt.Errorf(errMissingTenancy)
	}

	c.region = c.store.Region
	if c.region == "" {
		return fmt.Errorf(errMissingRegion)
	}

	return nil
}

func (vms *VaultManagementService) readSecret(ctx context.Context, id, path string) ([]byte, error) {
	if utils.IsNil(vms.Client) {
		return nil, fmt.Errorf(errUninitalizedOracleProvider)
	}
	vmsRequest := vault.GetSecretRequest{
		SecretId: &id,
	}
	secretOut, err := vms.Client.GetSecret(ctx, vmsRequest)
	if err != nil {
		return nil, util.SanitizeErr(err)
	}
	if path == "" {
		if *secretOut.SecretName != "" {
			return []byte(*secretOut.SecretName), nil
		}
		return nil, fmt.Errorf(errInvalidSecret, id)
	}
	var payload *string
	if secretOut.SecretName != nil {
		payload = secretOut.SecretName
	}
	payloadval := *payload
	val := gjson.Get(payloadval, path)
	if !val.Exists() {
		return nil, fmt.Errorf(errMissingKey, id)
	}
	return []byte(val.String()), nil
}

func (vms *VaultManagementService) GetSecret(ctx context.Context, ref esv1alpha1.ExternalSecretDataRemoteRef) (interface{}, error) {
	val, err := vms.readSecret(context.Background(), ref.Key, ref.Property)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (vms *VaultManagementService) GetSecretMap(ctx context.Context, ref esv1alpha1.ExternalSecretDataRemoteRef) (map[string]interface{}, error) {
	data, err := vms.readSecret(context.Background(), ref.Key, ref.Property)
	if err != nil {
		return nil, err
	}
	return serializer.UnmarshalJson(data)
}

// NewClient constructs a new secrets client based on the provided store.
func (vms *VaultManagementService) NewClient(ctx context.Context, store esv1alpha1.GenericStore, kube kclient.Client, namespace string) (provider.SecretsClient, error) {
	storeSpec := store.GetSpec()
	oracleSpec := storeSpec.Provider.Oracle

	oracleStore := &client{
		kube:      kube,
		store:     oracleSpec,
		namespace: namespace,
		storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	}
	if err := oracleStore.setAuth(ctx); err != nil {
		return nil, err
	}

	oracleTenancy := oracleStore.tenancy
	oracleUser := oracleStore.user
	oracleRegion := oracleStore.region
	oracleFingerprint := oracleStore.fingerprint
	oraclePrivateKey := oracleStore.privateKey

	configurationProvider := common.NewRawConfigurationProvider(oracleTenancy, oracleUser, oracleRegion, oracleFingerprint, oraclePrivateKey, nil)

	vaultManagementService, err := vault.NewVaultsClientWithConfigurationProvider(configurationProvider)
	if err != nil {
		return nil, fmt.Errorf(errOracleClient, err)
	}
	vms.Client = vaultManagementService
	return vms, nil
}

func (vms *VaultManagementService) Close(ctx context.Context) error {
	return nil
}

func init() {
	schema.Register(&VaultManagementService{}, &esv1alpha1.SecretStoreProvider{
		Oracle: &esv1alpha1.OracleProvider{},
	})
}
