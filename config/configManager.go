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

	ShowConfig()
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

func GetDefaultAllowed() AuthzValue {
	var defaultAllow AuthzValue

	for id, pol := range loadedConfig.ServiceConf.Policy {
		if id == "*" {
			defaultAllow = pol.Authz
			return defaultAllow
		}
	}

	return AuthzDeny
}

func GetAllowedIdentities() map[string]AuthzValue {
	allowed := make(map[string]AuthzValue)

	for id, pol := range loadedConfig.ServiceConf.Policy {
		if id != "*" {
			allowed[id] = pol.Authz
		}
	}
	return allowed
}

func GetPrometheusHTTPConfig() (bool, int) {
	return loadedConfig.Metrics.BindEnableFlag, loadedConfig.Metrics.BindPort
}

func GetLogFileConfig() (bool, string) {
	return loadedConfig.Log.LogOutputFileFlag, loadedConfig.Log.Path
}

func GetEnableDebug() bool {
	return loadedConfig.Log.Debug
}

func GetInsecureSkipVerify() bool {
	return loadedConfig.ServiceConf.Mtls.InsecSkipVerify
}

func GetMtlsEnable() bool {
	return loadedConfig.ServiceConf.Mtls.Enable
}

func GetIdentity() spiffeid.ID {
	return loadedConfig.Local.Identity
}

func GetServerSideFlag() bool {
	return loadedConfig.Local.ServerSideFlag
}

func GetLocalOnlyH1() bool {
	return loadedConfig.Local.H1Only
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
	loadedConfig.ServiceConf.Mtls.Enable = flag
}

func SetInsecureSkipVerify(flag bool) {
	loadedConfig.ServiceConf.Mtls.InsecSkipVerify = flag
}

func SetServerSideFlag(f bool) {
	loadedConfig.Local.ServerSideFlag = f
}

func SetIdentity(id spiffeid.ID) {
	loadedConfig.Local.Identity = id
}

func SetPolicy(policy map[string]PolicyData) {
	loadedConfig.ServiceConf.Policy = policy
}

func ShowConfig() {
	fmt.Println("printing initialized config printing config")
	json, err := json.MarshalIndent(loadedConfig, "", "    ")
	if err != nil {
		fmt.Println("failed to decode structure into json, error:", err)
	}
	fmt.Println(string(json))
}
