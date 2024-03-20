package config

import (
	"encoding/json"
	"fmt"

	"github.com/quicsec/quicsec/spiffeid"
)

var (
	loadedConfig *Config
)

func InitConfigManager() {
	var loader JSONLoader

	loader.Load()
	loadedConfig = loader.GetConfig()
}

func GetPathCertFile() string {
	return loadedConfig.Certs.CertPath
}

func GetPathKeyFile() string {
	return loadedConfig.Certs.KeyPath
}

func GetPathCAFile() string {
	return loadedConfig.Certs.CaPath
}

func GetAllowedIdentities() []string {
	var allowed []string
	for id, pol := range loadedConfig.ServiceConf.Policy {
		if id != "*" {
			if pol.Authz == AuthzAllow {
				allowed = append(allowed, id)
			}
		}
	}
	return allowed
}

func GetPrometheusHTTPConfig() (bool, int) {
	return loadedConfig.Metrics.BindEnabled, loadedConfig.Metrics.BindPort
}

func GetLogFileConfig() (bool, string) {
	return loadedConfig.Log.LogFileEnabled, loadedConfig.Log.Path
}

func GetEnableDebug() bool {
	return loadedConfig.Log.Debug
}

func GetInsecureSkipVerify() bool {
	return loadedConfig.ServiceConf.Mtls.InsecSkipVerify
}

func GetMtlsEnable() bool {
	return loadedConfig.ServiceConf.Mtls.MtlsEnabled
}

func GetIdentity() spiffeid.ID {
	return loadedConfig.Local.Identity
}

func GetServerSideFlag() bool {
	return loadedConfig.Local.ServerContext
}

func GetMetricsEnabled() bool {
	return loadedConfig.Metrics.Enable
}

func GetQuicDebugSecretFilePathEnabled() bool {
	return loadedConfig.Quic.Debug.SecretFilePathEnabled
}

func GetQuicDebugSecretFilePath() string {
	return loadedConfig.Quic.Debug.SecretFilePath
}

func GetQuicDebugQlogEnabled() bool {
	return loadedConfig.Quic.Debug.QlogEnabled
}

func GetQuicDebugQlogDirPath() string {
	return loadedConfig.Quic.Debug.QlogDirPath
}

func SetMtlsEnable(flag bool) {
	loadedConfig.ServiceConf.Mtls.MtlsEnabled = flag
}

func SetInsecureSkipVerify(flag bool) {
	loadedConfig.ServiceConf.Mtls.InsecSkipVerify = flag
}

func SetServerSideFlag(f bool) {
	loadedConfig.Local.ServerContext = f
}

func SetIdentity(id spiffeid.ID) {
	loadedConfig.Local.Identity = id
}

func SetPolicy(policy map[string]PolicyData) {
	loadedConfig.ServiceConf.Policy = policy
}

func GetExtAuthConfig(id string) *ExtAuthConfig {
	if policy, ok := loadedConfig.ServiceConf.Policy[id]; ok {
		return &policy.FilterChain.ExtAuth
	}
	return nil
}

func GetWafConfig(id string) *WafConfig {
	if policy, ok := loadedConfig.ServiceConf.Policy[id]; ok {
		return &policy.FilterChain.Waf
	}
	return nil
}

func GetOauth2Config(id string) *Oauth2Config {
	if policy, ok := loadedConfig.ServiceConf.Policy[id]; ok {
		return &policy.FilterChain.Oauth2
	}
	return nil
}

func GetFiltersChain(id string) []string {
	if policy, ok := loadedConfig.ServiceConf.Policy[id]; ok {
		return policy.FilterChain.FiltersAvb
	}
	return nil
}

func GetStarPolicyEnable() bool {
	policies := loadedConfig.ServiceConf.Policy

	for id := range  policies {
		if id == "*" {
			policy := policies[id]
			if policy.Authz == AuthzAllow {
				return true
			}
		}
	}

	return false
}

func ShowConfig() {
	fmt.Println("printing initialized config printing config")
	json, err := json.MarshalIndent(loadedConfig, "", "    ")
	if err != nil {
		fmt.Println("failed to decode structure into json, error:", err)
	}
	fmt.Println(string(json))
}

