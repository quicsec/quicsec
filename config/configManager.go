package config

import (
	"fmt"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Config struct {
	// Identity Manager
	// identityManager - certificates
	CertFile string `mapstructure:"CERT_FILE"`
	KeyFile  string `mapstructure:"KEY_FILE"`
	CAFile   string `mapstructure:"CA_FILE"`

	// Operations Manager
	// opsManager - metrics
	PrometheusEnableFlag bool
	MetricsEnableFlag    bool
	PrometheusBind       string `mapstructure:"PROMETHEUS_BIND"`
	MetricsEnable        int64  `mapstructure:"METRICS_ENABLE"`

	// opsManager - logs
	LogOutputFileFlag bool
	LogVerboseFlag    bool
	LogVerbose        int64  `mapstructure:"LOG_VERBOSE"`
	LogOutputFile     string `mapstructure:"LOG_FILE_PATH"`

	// opsManager - qlog
	QlogEnableFlag bool
	QlogDirPath    string `mapstructure:"QLOG_DIR_PATH"`

	// opsManager - shared secret dump
	SharedSecretEnableFlag bool
	SharedSecretFilePath   string `mapstructure:"SECRET_FILE_PATH"`

	// Authentication Manager
	// authManager - authz rules
	AuthzRulesPath string `mapstructure:"AUTHZ_RULES_PATH"`
	SpiffeID       []string
}

var onlyOnce sync.Once

// default config values
var globalConfig = Config{
	PrometheusEnableFlag:   false,
	QlogEnableFlag:         true,
	SharedSecretEnableFlag: false,
	LogOutputFileFlag:      false,
}

func GetPathCertFile() string {
	return globalConfig.CertFile
}

func GetPathKeyFile() string {
	return globalConfig.KeyFile
}

func GetPathCAFile() string {
	return globalConfig.CAFile
}

func GetLastAuthRules() []string {
	return globalConfig.SpiffeID
}

func GetPrometheusHTTPConfig() (bool, string) {
	return globalConfig.PrometheusEnableFlag, globalConfig.PrometheusBind
}

func GetLogFileConfig() (bool, string) {
	return globalConfig.LogOutputFileFlag, globalConfig.LogOutputFile
}

func GetEnableVerbose() bool {
	return globalConfig.LogVerboseFlag
}

func (c Config) showAuthzRules() {
	for _, id := range c.SpiffeID {
		fmt.Printf("URI:%s\n", id)
	}
}

func (c Config) ShowConfig() {
	fmt.Printf("Init configuration\n")
	fmt.Printf("CertFile:%s\n", c.CertFile)
	fmt.Printf("KeyFile:%s\n", c.KeyFile)
	fmt.Printf("CAFile:%s\n", c.CAFile)
	fmt.Printf("PrometheusBind:%s\n", c.PrometheusBind)
	fmt.Printf("LogVerbose:%d\n", c.LogVerbose)
	fmt.Printf("LogOutputFile:%s\n", c.LogOutputFile)
	fmt.Printf("MetricsEnable:%d\n", c.MetricsEnable)
	fmt.Printf("qlogDirPath:%s\n", c.QlogDirPath)
	fmt.Printf("sharedSecretFilePath:%s\n", c.SharedSecretFilePath)
	fmt.Printf("Authz rules:\n")
	c.showAuthzRules()
}

func LoadConfig() Config {
	onlyOnce.Do(func() {
		viper.AutomaticEnv()
		viper.SetEnvPrefix("QUICSEC")
		viper.AddConfigPath(".")
		viper.SetConfigType("json")
		viper.AllowEmptyEnv(true)

		// watch authz json file for changes
		viper.WatchConfig()
		viper.OnConfigChange(func(e fsnotify.Event) {
			globalConfig.SpiffeID = viper.GetStringSlice("quicsec.authz_rules")
		})

		//defaults
		viper.SetDefault("CERT_FILE", "certs/cert.pem")
		viper.SetDefault("KEY_FILE", "certs/cert.key")
		viper.SetDefault("CA_FILE", "certs/ca.pem")
		viper.SetDefault("METRICS_ENABLE", "1")
		viper.SetDefault("PROMETHEUS_BIND", "") // example: "192.168.56.101:8080"
		viper.SetDefault("LOG_VERBOSE", "1")
		viper.SetDefault("LOG_FILE_PATH", "") // example: output.log
		viper.SetDefault("QLOG_DIR_PATH", "./qlog/")
		viper.SetDefault("SECRET_FILE_PATH", "") // example: pre-shared-secret.txt
		viper.SetDefault("AUTHZ_RULES_PATH", "config.json")

		err := viper.Unmarshal(&globalConfig)
		if err != nil {
			fmt.Printf("environment cant be loaded: %s\n", err)
		}

		if globalConfig.AuthzRulesPath != "" {
			fmt.Printf("Read authz rules from: %s\n", globalConfig.AuthzRulesPath)
			viper.SetConfigName(globalConfig.AuthzRulesPath)
		}

		err = viper.ReadInConfig()
		if err != nil {
			fmt.Printf("cannot read cofiguration: %s\n", err)
		}

		globalConfig.SpiffeID = viper.GetStringSlice("quicsec.authz_rules")

		// pre shared secret
		if globalConfig.SharedSecretFilePath != "" {
			globalConfig.SharedSecretEnableFlag = true
		}
		// qlog dir
		if globalConfig.QlogDirPath == "" {
			globalConfig.QlogEnableFlag = false
		}

		// prometheus metrics
		if globalConfig.MetricsEnable == 1 {
			globalConfig.MetricsEnableFlag = true
		} else {
			globalConfig.MetricsEnableFlag = false
		}

		// prometheus metrics http
		if globalConfig.PrometheusBind != "" {
			globalConfig.PrometheusEnableFlag = true
		}

		// log into file
		if globalConfig.LogOutputFile != "" {
			globalConfig.LogOutputFileFlag = true
		} else {
			globalConfig.LogOutputFileFlag = false
		}

		// log verbose
		if globalConfig.LogVerbose == 1 {
			globalConfig.LogVerboseFlag = true
		} else {
			globalConfig.LogVerboseFlag = false
		}

	})

	return globalConfig
}
