package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/spf13/viper"
)

var onlyOnce sync.Once

const envVarPrefix string = "QUICSEC_"

type Config struct {
	Log      LogConfigs
	HTTP     HttpConfigs
	Quic     QuicConfigs
	Metrics  MetricsConfigs
	Certs    CertificatesConfigs
	Security SecurityConfigs
}

// opsManager - logs
type LogConfigs struct {
	LogOutputFileFlag       bool
	LogAccessOutputFileFlag bool
	Debug                   bool   `mapstructure:"debug"`
	Path                    string `mapstructure:"path"`
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
	SecretFilePathEnableFlag bool
	QlogEnableFlag           bool
	SecretFilePath           string `mapstructure:"secret_path"`
	QlogDirPath              string `mapstructure:"qlog_path"`
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

type SecurityConfigs struct {
	Mtls MtlsConfig `mapstructure:"mtls"`
}

type MtlsConfig struct {
	Enable          bool         `mapstructure:"enable"`
	InsecSkipVerify bool         `mapstructure:"insec_skip_verify"`
	Authz           AuthzConfigs `mapstructure:"authz"`
}

type AuthzConfigs struct {
	RulesPath string `mapstructure:"rules_path"`
	SpiffeID  []string
}

// default config values
var globalConfig = Config{
	Log: LogConfigs{
		LogOutputFileFlag:       false,
		LogAccessOutputFileFlag: false,
	},
	Quic: QuicConfigs{
		Debug: QuicDebugConfigs{
			SecretFilePathEnableFlag: false,
			QlogEnableFlag:           false,
		},
	},
	Metrics: MetricsConfigs{
		BindEnableFlag: false,
	},
}

func GetPathCertFile() string {
	return globalConfig.Certs.CertPath
}

func GetPathKeyFile() string {
	return globalConfig.Certs.KeyPath
}

func GetPathCAFile() string {
	return globalConfig.Certs.CaPath
}

func GetLastAuthRules() []string {
	return globalConfig.Security.Mtls.Authz.SpiffeID
}

func GetPrometheusHTTPConfig() (bool, int) {
	return globalConfig.Metrics.BindEnableFlag, globalConfig.Metrics.BindPort
}

func GetLogFileConfig() (bool, string) {
	return globalConfig.Log.LogOutputFileFlag, globalConfig.Log.Path
}

func GetEnableDebug() bool {
	return globalConfig.Log.Debug
}

func GetInsecureSkipVerify() bool {
	return globalConfig.Security.Mtls.InsecSkipVerify
}

func GetMtlsEnable() bool {
	return globalConfig.Security.Mtls.Enable
}

func SetMtlsEnable(flag bool) {
	globalConfig.Security.Mtls.Enable = flag
}

func SetLastAuthRules(spiffeURI []string) {
	globalConfig.Security.Mtls.Authz.SpiffeID = spiffeURI
}

func (c Config) ShowConfig() {
	fmt.Printf("Init configuration\n")

	fmt.Printf("LogVerbose:%t\n", c.Log.Debug)
	fmt.Printf("LogOutputFile:%s\n", c.Log.Path)
	fmt.Printf("LogAccessOutputFile:%s\n", c.HTTP.Access.Path)

	fmt.Printf("sharedSecretFilePath:%s\n", c.Quic.Debug.SecretFilePath)
	fmt.Printf("qlogDirPath:%s\n", c.Quic.Debug.QlogDirPath)

	fmt.Printf("MetricsEnable:%t\n", c.Metrics.Enable)
	fmt.Printf("BindPort:%d\n", c.Metrics.BindPort)

	fmt.Printf("CAPath:%s\n", c.Certs.CaPath)
	fmt.Printf("KeyPath:%s\n", c.Certs.KeyPath)
	fmt.Printf("CertPath:%s\n", c.Certs.CertPath)

	fmt.Printf("MtlsEnable:%t\n", c.Security.Mtls.Enable)
	fmt.Printf("InsecureSkipVerify:%t\n", c.Security.Mtls.InsecSkipVerify)
	fmt.Printf("AuthzRulesPath:%s\n", c.Security.Mtls.Authz.RulesPath)

}

// AuthzConfig struct to parse the authz json file
type AuthzConfig struct {
	Quicsec AuthzQuicsecConfig `json:"quicsec"`
}

type AuthzQuicsecConfig struct {
	AuthzRules []string `json:"authz_rules"`
}

func readAuthzRulesFile(path string, confLog logr.Logger) {
	var config AuthzConfig
	jsonFile, err := os.Open(path)
	if err != nil {
		confLog.V(log.DebugLevel).Error(err, "failed to os.Open()")
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	json.Unmarshal(byteValue, &config)
	SetLastAuthRules(config.Quicsec.AuthzRules)
}

func watchAuthzRules(rulesPath string, confLog logr.Logger) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		confLog.V(log.DebugLevel).Error(err, "failed to fsnotify.NewWatcher()")
	}
	defer watcher.Close()
	err = watcher.Add(rulesPath)
	if err != nil {
		confLog.V(log.DebugLevel).Error(err, "failed to watcher.Add():", "path", rulesPath)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				readAuthzRulesFile(rulesPath, confLog)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			confLog.V(log.DebugLevel).Error(err, "watcher errors:")
		}
	}
}

func readCoreConfig() (string, string, string) {
	var dir string
	var file string
	var coreConfigFull string

	coreConfig := os.Getenv(envVarPrefix + "CORE_CONFIG")
	if coreConfig != "" {
		coreConfigFull = coreConfig
		// Check if file already exists
		dir, file = filepath.Split(coreConfig)
		// remove "json" from the file
		file = strings.Split(file, ".")[0]
	} else {
		// default value ./config
		coreConfigFull = "./config.json"
		dir = "./"
		file = "config"
	}
	return dir, file, coreConfigFull
}

func LoadConfig() Config {
	onlyOnce.Do(func() {
		var confLogger logr.Logger
		// read QUICSEC_CORE_CONFIG before viper init
		path, configFile, configCorePath := readCoreConfig()

		viper.AddConfigPath(path)
		viper.SetConfigName(configFile) // Register config file name (no extension)
		viper.SetConfigType("json")     // Look for specific type

		// defaults
		viper.SetDefault("log.debug", true)                                      // QUICSEC_LOG_DEBUG
		viper.SetDefault("log.path", "")                                         // QUICSEC_LOG_PATH
		viper.SetDefault("http.access.path", "")                                 // QUICSEC_HTTP_ACCESS_PATH
		viper.SetDefault("quic.debug.secret_path", "")                           // QUICSEC_QUIC_DEBUG_SECRET_PATH
		viper.SetDefault("quic.debug.qlog_path", "./qlog/")                      // QUICSEC_QUIC_DEBUG_QLOG_PATH
		viper.SetDefault("metrics.enable", true)                                 // QUICSEC_METRICS_ENABLE
		viper.SetDefault("metrics.bind_port", 8080)                              // QUICSEC_METRICS_BIND_PORT
		viper.SetDefault("certs.ca_path", "certs/ca.pem")                        // QUICSEC_CERTS_CA_PATH
		viper.SetDefault("certs.key_path", "certs/cert.key")                     // QUICSEC_CERTS_KEY_PATH
		viper.SetDefault("certs.cert_path", "certs/cert.pem")                    // QUICSEC_CERTS_CERT_PATH
		viper.SetDefault("security.mtls.enable", false)                          // QUICSEC_SECURITY_MTLS_ENABLE
		viper.SetDefault("security.mtls.insec_skip_verify", false)               // QUICSEC_SECURITY_MTLS_INSEC_SKIP_VERIFY
		viper.SetDefault("security.mtls.authz.rules_path", "./authzconfig.json") // QUICSEC_SECURITY_MTLS_AUTHZ_RULES_PATH

		if err := viper.ReadInConfig(); err != nil {
			fmt.Println("config: error reading config file: " + err.Error())
		} else {
			// watch authz json file for changes
			viper.WatchConfig()
			viper.OnConfigChange(func(e fsnotify.Event) {
				enableFlag := viper.GetBool("security.mtls.enable")
				SetMtlsEnable(enableFlag)
				confLogger.V(log.DebugLevel).Info("mTLS config change", "enable", enableFlag)
			})
		}

		for _, key := range viper.AllKeys() {
			envKey := strings.ToUpper(envVarPrefix + strings.ReplaceAll(key, ".", "_"))
			err := viper.BindEnv(key, envKey)
			if err != nil {
				fmt.Println("config: unable to bind env: " + err.Error())
			}
		}

		if err := viper.Unmarshal(&globalConfig); err != nil {
			fmt.Println("config: unable to decode into struct: " + err.Error())
		}

		// log into file
		if globalConfig.Log.Path != "" {
			globalConfig.Log.LogOutputFileFlag = true
		} else {
			globalConfig.Log.LogOutputFileFlag = false
		}

		log.InitLoggerLogr(globalConfig.Log.Debug, globalConfig.Log.Path)

		log.InitLoggerRequest(globalConfig.Log.Debug, globalConfig.HTTP.Access.Path)

		confLogger = log.LoggerLgr.WithName(log.ConstConfigManager)
		confLogger.V(log.DebugLevel).Info("all environment variables loaded")
		confLogger.V(log.DebugLevel).Info("core config", "path", configCorePath)
		rulesPath := globalConfig.Security.Mtls.Authz.RulesPath
		if rulesPath != "" {
			confLogger.V(log.DebugLevel).Info("authz rules config", "path", rulesPath)
			readAuthzRulesFile(rulesPath, confLogger)
			go watchAuthzRules(rulesPath, confLogger)
		}

		// pre shared secret
		if globalConfig.Quic.Debug.SecretFilePath != "" {
			globalConfig.Quic.Debug.SecretFilePathEnableFlag = true
		}
		// qlog dir
		if globalConfig.Quic.Debug.QlogDirPath == "" {
			globalConfig.Quic.Debug.QlogEnableFlag = false
		}

		// prometheus metrics http
		if globalConfig.Metrics.BindPort != 0 {
			globalConfig.Metrics.BindEnableFlag = true
		}

		// log http requests into file
		if globalConfig.HTTP.Access.Path != "" {
			globalConfig.Log.LogAccessOutputFileFlag = true
		} else {
			globalConfig.Log.LogAccessOutputFileFlag = false
		}

		confLogger.V(log.DebugLevel).Info("all configuration loaded")

	})

	return globalConfig
}
