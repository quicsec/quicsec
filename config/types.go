package config

import (
	"github.com/quicsec/quicsec/spiffeid"
)

type AuthzValue string

const (
	AuthzAllow AuthzValue = "allow"
	AuthzDeny  AuthzValue = "deny"
)

type Config struct {
	Version     string
	ServiceConf ServiceConf `mapstructure:"serviceconf"`
	Log         LogConfigs
	HTTP        HttpConfigs
	Quic        QuicConfigs
	Metrics     MetricsConfigs
	Certs       CertificatesConfigs
	Local       LocalConfigs
}

type ServiceConf struct {
	ConfSelector string                `mapstructure:"conf_selector"`
	Policy       map[string]PolicyData `mapstructure:"policy"`
	Mtls         MtlsConfig
}

// opsManager - logs
type LogConfigs struct {
	LogOutputFileFlag       bool
	LogAccessOutputFileFlag bool
	Debug                   bool   `mapstructure:"debug"`
	Path                    string `mapstructure:"path"`
}

type PolicyData struct {
	Authz AuthzValue `mapstructure:"authz"`
}

type HttpConfigs struct {
	Access AccessConfigs `mapstructure:"access"`
}

type AccessConfigs struct {
	Path string `mapstructure:"path"`
}

// opsManager - shared secret dump
type QuicConfigs struct {
	Debug QuicDebugConfigs `mapstructure:"debug"`
}

// opsManager - shared secret dump
type QuicDebugConfigs struct {
	SecretFilePathEnabled bool
	SecretFilePath        string `mapstructure:"secret_path"`
	QlogEnabled           bool
	QlogDirPath           string `mapstructure:"qlog_path"`
}

// Operations Manager
// opsManager - metrics
type MetricsConfigs struct {
	BindEnableFlag bool
	Enable         bool `mapstructure:"enable"`
	BindPort       int  `mapstructure:"bind_port"`
}

// Identity Manager
// identityManager - certificates
type CertificatesConfigs struct {
	CaPath   string `mapstructure:"ca_path"`
	KeyPath  string `mapstructure:"key_path"`
	CertPath string `mapstructure:"cert_path"`
}

type MtlsConfig struct {
	Enable          bool `mapstructure:"client_cert"` //[TODO] client_cert refers to require client certificate on server contex but refers to mtls enabled on both context. ?
	InsecSkipVerify bool `mapstructure:"insec_skip_verify"`
}

// LocalConfigs
type LocalConfigs struct {
	// Identity (x509)
	Identity spiffeid.ID

	// Server=1/Client=0
	ServerSideFlag bool

	// Open only H1 server (no H3)
	H1Only bool
}
