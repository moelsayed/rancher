package client

const (
	ResourceConfigurationType           = "resourceConfiguration"
	ResourceConfigurationFieldKeys      = "keys"
	ResourceConfigurationFieldProviders = "providers"
	ResourceConfigurationFieldResources = "resources"
)

type ResourceConfiguration struct {
	Keys      []Key                   `json:"keys,omitempty" yaml:"keys,omitempty"`
	Providers []ProviderConfiguration `json:"providers,omitempty" yaml:"providers,omitempty"`
	Resources []string                `json:"resources,omitempty" yaml:"resources,omitempty"`
}
