package client

const (
	AESConfigurationType      = "aesConfiguration"
	AESConfigurationFieldFoos = "foos"
)

type AESConfiguration struct {
	Foos []Foo `json:"foos,omitempty" yaml:"foos,omitempty"`
}
