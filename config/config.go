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
	Http        HttpConfigs
	Quic        QuicConfigs
	Metrics     MetricsConfigs
	Certs       CertificatesConfigs
	Local       LocalConfigs
}

type ServiceConf struct {
	ConfSelector string                `mapstructure:"conf_selector"`
	Policy       map[string]PolicyData `mapstructure:"policy"`
	Mtls         MtlsConfig            `mapstructure:"mtls"`
}

type PolicyData struct {
	Authz       AuthzValue    `mapstructure:"authz"`
	FilterChain FiltersConfig `mapstructure:"filters"`
}

type FiltersConfig struct {
	FiltersAvb []string
	Waf        WafConfig     `mapstructure:"waf"`
	ExtAuth    ExtAuthConfig `mapstructure:"ext_auth"`
	Oauth2     Oauth2Config  `mapstructure:"oauth2"`
}

type WafConfig struct {
	Coraza []string `mapstructure:"waf"`
}

type ExtAuthConfig struct {
	Opa OpaConfig `mapstructure:"opa"`
}

type OpaConfig struct {
	Url                 string `mapstructure:"url"`
	Auth                string `mapstructure:"auth"`
	PassJwtClaims       string `mapstructure:"pass_jwt_claims"`
	PassServiceIdentity string `mapstructure:"pass_svc_identity"`
	PassClientIdentity  string `mapstructure:"pass_cli_identity"`
}

type Oauth2Config struct {
	ClientId     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	AuthzEp      string   `mapstructure:"authz_endpoint"`
	TokenEp      string   `mapstructure:"token_endpoint"`
	RedirectURL  string   `mapstructure:"redirect_url"`
	Scopes       []string `mapstructure:"scopes"`
}

type MtlsConfig struct {
	MtlsEnabled     bool `mapstructure:"client_cert"`
	InsecSkipVerify bool `mapstructure:"insec_skip_verify"`
}

// opsManager - logs
type LogConfigs struct {
	LogFileEnabled       bool
	AccessLogFileEnabled bool
	Debug                bool   `mapstructure:"debug"`
	Path                 string `mapstructure:"path"`
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
	BindEnabled bool
	Enable      bool `mapstructure:"enable"`
	BindPort    int  `mapstructure:"bind_port"`
}

// Identity Manager
// identityManager - certificates
type CertificatesConfigs struct {
	CaPath   string `mapstructure:"ca_path"`
	KeyPath  string `mapstructure:"key_path"`
	CertPath string `mapstructure:"cert_path"`
}

// LocalConfigs
type LocalConfigs struct {
	Identity      spiffeid.ID
	ServerContext bool
}
