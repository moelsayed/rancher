package client

const (
	SecretsEncryptionConfigType              = "secretsEncryptionConfig"
	SecretsEncryptionConfigFieldCustomConfig = "customConfig"
	SecretsEncryptionConfigFieldEnabled      = "enabled"
)

type SecretsEncryptionConfig struct {
	CustomConfig string `json:"customConfig,omitempty" yaml:"customConfig,omitempty"`
	Enabled      bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}
