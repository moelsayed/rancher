package cluster

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	normantypes "github.com/rancher/norman/types"
	"github.com/rancher/rke/k8s"
	"github.com/rancher/rke/log"
	"github.com/rancher/rke/services"
	"github.com/rancher/rke/templates"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiserverconfig "k8s.io/apiserver/pkg/apis/config"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

const (
	EncryptionProviderFilePath = "/etc/kubernetes/ssl/encryption.yaml"
)

type encryptionKey struct {
	Name   string
	Secret string
}
type keyList struct {
	KeyList []*encryptionKey
}

func ReconcileEncryptionProviderConfig(ctx context.Context, kubeCluster, currentCluster *Cluster) error {
	if len(kubeCluster.ControlPlaneHosts) == 0 {
		return nil
	}
	// New or existing cluster deployment with encryption enabled. We will rewrite the secrets after deploying the addons.
	if (currentCluster == nil || !currentCluster.IsEncryptionEnabled()) &&
		kubeCluster.IsEncryptionEnabled() {
		kubeCluster.EncryptionConfig.RewriteSecrets = true
		return nil
	}
	// encryption is disabled
	if !kubeCluster.IsEncryptionEnabled() && !currentCluster.IsEncryptionEnabled() {
		return nil
	}
	// disable encryption
	if !kubeCluster.IsEncryptionEnabled() && currentCluster.IsEncryptionEnabled() {
		if currentCluster.IsEncryptionCustomConfig() {
			// KubeAPI will be restarted for the last time during controlplane redeployment, since the
			// Configuration file is now empty, the Process Plan will change.
			kubeCluster.EncryptionConfig.EncryptionProviderFile = ""
			return kubeCluster.DeployEncryptionProviderFile(ctx)
		}
		return kubeCluster.DisableSecretsEncryption(ctx, currentCluster)
	}
	return nil
}

func (c *Cluster) DisableSecretsEncryption(ctx context.Context, currentCluster *Cluster) error {
	if len(c.ControlPlaneHosts) == 0 {
		return nil
	}
	var err error
	c.EncryptionConfig.EncryptionProviderFile, err = currentCluster.generateDisabledEncryptionProviderFile()
	if err != nil {
		return err
	}
	if err := c.DeployEncryptionProviderFile(ctx); err != nil {
		return err
	}
	if err := services.RestartKubeAPIWithHealthcheck(ctx, c.ControlPlaneHosts, c.LocalConnDialerFactory, c.Certificates); err != nil {
		return err
	}
	if err := c.RewriteSecrets(ctx); err != nil {
		return err
	}
	// KubeAPI will be restarted for the last time during controlplane redeployment, since the
	// Configuration file is now empty, the Process Plan will change.
	c.EncryptionConfig.EncryptionProviderFile = ""
	return c.DeployEncryptionProviderFile(ctx)

}

func (c *Cluster) RewriteSecrets(ctx context.Context) error {
	log.Infof(ctx, "Rewriting cluster secrets")
	k8sClient, err := k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
	if err != nil {
		return fmt.Errorf("Failed to initialize new kubernetes client: %v", err)
	}
	secretsList, err := k8s.GetSecretsList(k8sClient, "")
	if err != nil {
		return err
	}
	for _, secret := range secretsList.Items {
		err := rewriteSecret(k8sClient, &secret)
		if err != nil {
			return err
		}
	}
	log.Infof(ctx, "Cluster secrets rewritten successfully")
	return nil
}

func (c *Cluster) RotateEncryptionKey(ctx context.Context, fullState *FullState) error {
	//generate new key
	newKey, err := generateEncryptionKey()
	if err != nil {
		return err
	}
	oldKey, err := c.extractActiveKey(c.EncryptionConfig.EncryptionProviderFile)
	if err != nil {
		return err
	}
	// reverse the keys order in the file, making newKey the Active Key
	initialKeyList := []*encryptionKey{ // order is critical here!
		newKey,
		oldKey,
	}
	initialProviderConfig, err := providerFileFromKeyList(keyList{KeyList: initialKeyList})
	if err != nil {
		return err
	}
	c.EncryptionConfig.EncryptionProviderFile = initialProviderConfig
	if err := c.DeployEncryptionProviderFile(ctx); err != nil {
		return err
	}
	// commit to state as soon as possible
	if err := c.UpdateClusterCurrentState(ctx, fullState); err != nil {
		return err
	}
	if err := services.RestartKubeAPIWithHealthcheck(ctx, c.ControlPlaneHosts, c.LocalConnDialerFactory, c.Certificates); err != nil {
		return err
	}
	// rewrite secrets
	if err := c.RewriteSecrets(ctx); err != nil {
		return err
	}
	// At this point, all secrets have been rewritten using the newKey, so we remove the old one.
	finalKeyList := []*encryptionKey{
		newKey,
	}
	finalProviderConfig, err := providerFileFromKeyList(keyList{KeyList: finalKeyList})
	if err != nil {
		return err
	}
	c.EncryptionConfig.EncryptionProviderFile = finalProviderConfig
	if err := c.DeployEncryptionProviderFile(ctx); err != nil {
		return err
	}
	// commit to state
	if err := c.UpdateClusterCurrentState(ctx, fullState); err != nil {
		return err
	}
	if err := services.RestartKubeAPIWithHealthcheck(ctx, c.ControlPlaneHosts, c.LocalConnDialerFactory, c.Certificates); err != nil {
		return err
	}
	return nil
}

func (c *Cluster) DeployEncryptionProviderFile(ctx context.Context) error {
	return deployFile(ctx, c.ControlPlaneHosts, c.SystemImages.Alpine, c.PrivateRegistriesMap, EncryptionProviderFilePath, c.EncryptionConfig.EncryptionProviderFile)
}

// ReconcileDesiredStateEncryptionConfig We do the rotation outside of the cluster reconcile logic. When we are done,
// DesiredState needs to be updated to reflect the "new" configuration
func (c *Cluster) ReconcileDesiredStateEncryptionConfig(ctx context.Context, fullState *FullState) error {
	fullState.DesiredState.EncryptionConfig = c.EncryptionConfig.EncryptionProviderFile
	return fullState.WriteStateFile(ctx, c.StateFilePath)
}

func (c *Cluster) IsEncryptionEnabled() bool {
	if c == nil {
		return false
	}
	if c.Services.KubeAPI.SecretsEncryptionConfig != nil &&
		c.Services.KubeAPI.SecretsEncryptionConfig.Enabled {
		return true
	}
	return false
}
func (c *Cluster) IsEncryptionCustomConfig() bool {
	if c.IsEncryptionEnabled() &&
		c.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig != nil {
		return true
	}
	return false
}

func (c *Cluster) getEncryptionProviderFile() (string, error) {
	if c.EncryptionConfig.EncryptionProviderFile != "" {
		return c.EncryptionConfig.EncryptionProviderFile, nil
	}
	key, err := generateEncryptionKey()
	if err != nil {
		return "", err
	}
	c.EncryptionConfig.EncryptionProviderFile, err = providerFileFromKeyList(keyList{KeyList: []*encryptionKey{key}})
	return c.EncryptionConfig.EncryptionProviderFile, err
}

func (c *Cluster) extractActiveKey(s string) (*encryptionKey, error) {
	config := apiserverconfig.EncryptionConfiguration{}
	if err := k8s.DecodeYamlResource(&config, c.EncryptionConfig.EncryptionProviderFile); err != nil {
		return nil, err
	}
	resource := config.Resources[0]
	provider := resource.Providers[0]
	return &encryptionKey{
		Name:   provider.AESCBC.Keys[0].Name,
		Secret: provider.AESCBC.Keys[0].Secret,
	}, nil
}

func (c *Cluster) generateDisabledEncryptionProviderFile() (string, error) {
	key, err := c.extractActiveKey(c.EncryptionConfig.EncryptionProviderFile)
	if err != nil {
		return "", err
	}
	return disabledProviderFileFromKey(key)
}

func rewriteSecret(k8sClient *kubernetes.Clientset, secret *v1.Secret) error {
	var err error
	if err = k8s.UpdateSecret(k8sClient, secret); err == nil {
		return nil
	}
	if apierrors.IsConflict(err) {
		secret, err = k8s.GetSecret(k8sClient, secret.Name, secret.Namespace)
		if err != nil {
			return err
		}
		err = k8s.UpdateSecret(k8sClient, secret)
	}
	return err
}

func generateEncryptionKey() (*encryptionKey, error) {
	// TODO: do this in a better way
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return &encryptionKey{
		Name:   normantypes.GenerateName("key"),
		Secret: base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%X", buf))),
	}, nil
}

func isEncryptionEnabled(rkeConfig *v3.RancherKubernetesEngineConfig) bool {
	if rkeConfig.Services.KubeAPI.SecretsEncryptionConfig != nil &&
		rkeConfig.Services.KubeAPI.SecretsEncryptionConfig.Enabled {
		return true
	}
	return false
}
func isEncryptionCustomConfig(rkeConfig *v3.RancherKubernetesEngineConfig) bool {
	if isEncryptionEnabled(rkeConfig) &&
		rkeConfig.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig != nil {
		return true
	}
	return false
}

func providerFileFromKeyList(keyList interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.MultiKeyEncryptionProviderFile, keyList)
}

func disabledProviderFileFromKey(keyList interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.DisabledEncryptionProviderFile, keyList)
}

func (c *Cluster) readEncryptionCustomConfig(ctx context.Context, flags ExternalFlags) (string, error) {
	customConfig := apiserverconfig.EncryptionConfiguration{
		TypeMeta:  c.RancherKubernetesEngineConfig.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig.TypeMeta,
		Resources: c.RancherKubernetesEngineConfig.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig.Resources,
	}
	jsonConfigr, _ := json.Marshal(customConfig)
	logrus.Infof("melsayed------------------------------------------------ in resources %v", string(jsonConfigr))
	yamlConfirg, _ := yaml.JSONToYAML(jsonConfigr)
	logrus.Infof("melsayed------------------------------------------------ in resources %v", string(yamlConfirg))

	jsonConfig, err := json.Marshal(customConfig)
	if err != nil {
		return "", err
	}
	yamlConfig, err := yaml.JSONToYAML(jsonConfig)
	if err != nil {
		return "", nil
	}

	return string(yamlConfig), nil
	// var r map[string]interface{}
	// var clusterFile, jsonConfig, customConfig []byte
	// var err error
	// logrus.Infof("melsayed------------------------------------------------ in readEncryptionCustomConfig %v", c.RancherKubernetesEngineConfig.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig.String())
	//
	// file, err := os.Open(c.ConfigDir)
	// if err == nil {
	// 	clusterFile, err = ioutil.ReadAll(file)
	// 	defer file.Close()
	// 	if err != nil {
	// 		return "", fmt.Errorf("failed to read file: %v", err)
	// 	}
	// 	err = yaml.Unmarshal(clusterFile, &r)
	// 	if err != nil {
	// 		return "", fmt.Errorf("error unmarshalling: %v", err)
	// 	}
	// 	services := r["services"].(map[string]interface{})
	// 	kubeapi := services["kube-api"].(map[string]interface{})
	// 	sec := kubeapi["secrets_encryption_config"].(map[string]interface{})
	// 	jsonConfig, err = json.Marshal(sec["custom_config"])
	// 	if err != nil {
	// 		return "", fmt.Errorf("error marshalling: %v", err)
	// 	}
	// } else {
	// 	log.Warnf(ctx, "can not find cluster configuration file: %v", err)
	// 	log.Infof(ctx, "Falling back to RancherKubernetesConfig for EncryptionCustomConfig")
	// 	clusterFile, err = yaml.Marshal(c.RancherKubernetesEngineConfig)
	// 	if err != nil {
	// 		return "", fmt.Errorf("error marshalling: %v", err)
	// 	}
	// 	err = yaml.Unmarshal(clusterFile, &r)
	// 	if err != nil {
	// 		return "", fmt.Errorf("error unmarshalling: %v", err)
	// 	}
	// 	services := r["services"].(map[string]interface{})
	// 	kubeapi := services["kubeApi"].(map[string]interface{})
	// 	sec := kubeapi["secretsEncryptionConfig"].(map[string]interface{})
	// 	jsonConfig, err = json.Marshal(sec["customConfig"])
	// 	if err != nil {
	// 		return "", fmt.Errorf("error marshalling: %v", err)
	// 	}
	// }
	//
	// customConfig, err = yaml.JSONToYAML(jsonConfig)
	//
	// return string(customConfig), err
}
