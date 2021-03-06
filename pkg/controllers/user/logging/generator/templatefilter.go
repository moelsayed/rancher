package generator

var FilterTemplate = `
{{define "filter-rke"}}
<filter {{ .RkeLogTag }}.**>
  @type record_transformer
  enable_ruby true  
  <record>
    tag ${tag}
    log_type k8s_infrastructure_container 
    driver rke
    component ${tag_suffix[6].split("_")[0]}
    container_id ${tag_suffix[6].split(".")[0]}
  </record>
</filter>

<filter {{ .RkeLogTag }}.**>
  @type prometheus
  <metric>
    name fluentd_input_status_num_records_total
    type counter
    desc The total number of incoming records
    <labels>
      tag ${tag}
      hostname ${hostname}
    </labels>
  </metric>
</filter>
{{end}}

{{define "filter-container"}}
<filter  {{ .ContainerLogSourceTag }}.**>
  @type  kubernetes_metadata
  merge_json_log  true
  preserve_json_log  true
</filter>
{{end}}

{{define "filter-custom-tags"}}
<filter {{ .ContainerLogSourceTag }}.**>
  @type record_transformer
  <record>
    tag ${tag}
    log_type k8s_normal_container 
    {{- range $k, $val := .OutputTags }}
    {{$k}}  {{$val | escapeString}}
    {{end}}
  </record>
</filter>
{{end}}

{{define "filter-prometheus"}}
<filter {{ .ContainerLogSourceTag }}.**>
  @type prometheus
  <metric>
    name fluentd_input_status_num_records_total
    type counter
    desc The total number of incoming records
    <labels>
      tag ${tag}
      hostname ${hostname}
    </labels>
  </metric>
</filter>
{{end}}

{{define "filter-sumo"}}
{{- if eq .CurrentTarget "syslog"}}
{{- if .SyslogConfig.Token}}
<filter  {{ .ContainerLogSourceTag }}.** {{ .CustomLogSourceTag}}.** {{ if .IncludeRke }}{{ .RkeLogTag }}.**{{end}} >
  @type record_transformer
  <record>
    tag ${tag} {{.SyslogConfig.Token}}
  </record>
</filter>
{{end}}
{{end}}
{{end}}

{{define "filter-exclude-system-component"}}
{{- if not .IncludeRke }}
<filter {{ .ContainerLogSourceTag }}.**>
  @type grep
  <exclude>
    key $.kubernetes.namespace_name
    pattern {{.ExcludeNamespace}}
  </exclude>
</filter>
{{end}}
{{end}}

{{define "filter-project-namespace"}}
<filter {{ .ContainerLogSourceTag}}.**>
  @type record_transformer
  enable_ruby  true
  <record>
    tag ${tag}
    namespace ${record["kubernetes"]["namespace_name"]}
    projectID {{ .ContainerLogSourceTag}}
  </record>
</filter>

<filter {{ .ContainerLogSourceTag}}.**>
  @type grep
  <regexp>
    key namespace
    pattern {{.GrepNamespace}}
  </regexp>
</filter>

<filter {{ .ContainerLogSourceTag}}.**>
  @type record_transformer
  remove_keys namespace
</filter>
{{end}}
`
