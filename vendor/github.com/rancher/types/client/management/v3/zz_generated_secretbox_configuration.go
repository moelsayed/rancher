package client

const (
	SecretboxConfigurationType      = "secretboxConfiguration"
	SecretboxConfigurationFieldFoos = "foos"
)

type SecretboxConfiguration struct {
	Foos []Foo `json:"foos,omitempty" yaml:"foos,omitempty"`
}
