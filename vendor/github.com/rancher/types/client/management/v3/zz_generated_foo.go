package client

const (
	FooType      = "foo"
	FooFieldBar  = "bar"
	FooFieldName = "name"
)

type Foo struct {
	Bar  string `json:"bar,omitempty" yaml:"bar,omitempty"`
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}
