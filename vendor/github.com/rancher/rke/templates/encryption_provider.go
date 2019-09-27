package templates

const (
	DisabledEncryptionProviderFile = `apiVersion: v1
kind: EncryptionConfig
resources:
- resources:
  - secrets
  providers:
  - identity: {}
  - aescbc:
      keys:
      - name: {{.Name}}
        secret: {{.Secret}}`
	MultiKeyEncryptionProviderFile = `apiVersion: v1
kind: EncryptionConfig
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
{{- range $i, $v:= .KeyList}}
      - name: {{ $v.Name}}
        secret: {{ $v.Secret -}}
{{end}}
  - identity: {}`
)
