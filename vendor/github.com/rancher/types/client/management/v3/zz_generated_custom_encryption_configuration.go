package client

const (
	CustomEncryptionConfigurationType           = "customEncryptionConfiguration"
	CustomEncryptionConfigurationFieldResources = "resources"
)

type CustomEncryptionConfiguration struct {
	Resources []ResourceConfiguration `json:"resources,omitempty" yaml:"resources,omitempty"`
}
