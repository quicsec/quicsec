package config

import (
	"fmt"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/quicsec/quicsec/spiffeid"
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
	LogOutputFileFlag       bool
	LogAccessOutputFileFlag bool
	LogDebugFlag            bool
	LogDebug                int64  `mapstructure:"LOG_DEBUG"`
	LogOutputFile           string `mapstructure:"LOG_FILE_PATH"`
	LogAccessOutputFile     string `mapstructure:"LOG_ACCESS_PATH"`

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

	//mTLS
	//Skip CA certificate verification
	InsecureSkipVerifyFlag bool
	InsecureSkipVerify     uint64 `mapstructure:"INSEC_SKIP_VERIFY"`
	//[TODO] After implementing CABundle custom verify, this flag should
	// configure the custom verification and not that one from cypto/tls

	// mTLS enable
	MTlsEnableFlag bool
	MTlsEnable     uint64 `mapstructure:"MTLS_ENABLE"`

	// Identity (x509)
	Identity spiffeid.ID

	// Server=1
	// Client=0
	ServerSideFlag bool
}

var onlyOnce sync.Once

// default config values
var globalConfig = Config{
	PrometheusEnableFlag:    false,
	QlogEnableFlag:          true,
	SharedSecretEnableFlag:  false,
	LogOutputFileFlag:       false,
	LogAccessOutputFileFlag: false,
	InsecureSkipVerifyFlag:  false,
	MTlsEnableFlag:          true,
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

func GetEnableDebug() bool {
	return globalConfig.LogDebugFlag
}

func GetInsecureSkipVerify() bool {
	return globalConfig.InsecureSkipVerifyFlag
}

func GetMtlsEnable() bool {
	return globalConfig.MTlsEnableFlag
}

func GetIdentity() spiffeid.ID {
	return globalConfig.Identity
}

func SetIdentity(id spiffeid.ID) {
	globalConfig.Identity = id
}

func GetServerSideFlag() bool {
	return globalConfig.ServerSideFlag
}

func SetServerSideFlag(f bool) {
	globalConfig.ServerSideFlag = f
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
	fmt.Printf("LogVerbose:%d\n", c.LogDebug)
	fmt.Printf("LogOutputFile:%s\n", c.LogOutputFile)
	fmt.Printf("LogAccessOutputFile:%s\n", c.LogAccessOutputFile)
	fmt.Printf("MetricsEnable:%d\n", c.MetricsEnable)
	fmt.Printf("qlogDirPath:%s\n", c.QlogDirPath)
	fmt.Printf("InsecureSkipVerify:%d\n", c.InsecureSkipVerify)
	fmt.Printf("MtlsEnable:%d\n", c.MTlsEnable)
	fmt.Printf("sharedSecretFilePath:%s\n", c.SharedSecretFilePath)
	fmt.Printf("Authz rules:\n")
	c.showAuthzRules()
}

func LoadConfig() Config {
	onlyOnce.Do(func() {
		viper.AutomaticEnv()
		viper.SetEnvPrefix("QUICSEC")
		viper.AddConfigPath("/")
		viper.SetConfigType("json")
		viper.AllowEmptyEnv(true)

		//defaults
		viper.SetDefault("CERT_FILE", "certs/cert.pem")
		viper.SetDefault("KEY_FILE", "certs/cert.key")
		viper.SetDefault("CA_FILE", "certs/ca.pem")
		viper.SetDefault("METRICS_ENABLE", "1")
		viper.SetDefault("PROMETHEUS_BIND", "") // example: "192.168.56.101:8080"
		viper.SetDefault("LOG_DEBUG", "1")
		viper.SetDefault("LOG_FILE_PATH", "")   // example: output.log
		viper.SetDefault("LOG_ACCESS_PATH", "") // example: /var/log/access.log
		viper.SetDefault("QLOG_DIR_PATH", "./qlog/")
		viper.SetDefault("SECRET_FILE_PATH", "") // example: pre-shared-secret.txt
		viper.SetDefault("AUTHZ_RULES_PATH", "config.json")
		viper.SetDefault("INSEC_SKIP_VERIFY", "0")
		viper.SetDefault("MTLS_ENABLE", "1")

		err := viper.Unmarshal(&globalConfig)
		if err != nil {
			fmt.Printf("environment cant be loaded: %s\n", err)
		}

		// log debug
		if globalConfig.LogDebug == 1 {
			globalConfig.LogDebugFlag = true
		} else {
			globalConfig.LogDebugFlag = false
		}

		// log into file
		if globalConfig.LogOutputFile != "" {
			globalConfig.LogOutputFileFlag = true
		} else {
			globalConfig.LogOutputFileFlag = false
		}

		log.InitLoggerLogr(globalConfig.LogDebugFlag, globalConfig.LogOutputFile)
		log.InitLoggerRequest(globalConfig.LogDebugFlag, globalConfig.LogAccessOutputFile)
		confLogger := log.LoggerLgr.WithName(log.ConstConfigManager)
		confLogger.V(log.DebugLevel).Info("all environment variables loaded")

		if globalConfig.AuthzRulesPath != "" {
			confLogger.V(log.DebugLevel).Info("Read authz rules", "path", globalConfig.AuthzRulesPath)
			viper.SetConfigName(globalConfig.AuthzRulesPath)
		}

		err = viper.ReadInConfig()
		if err != nil {
			confLogger.V(log.DebugLevel).Info("cannot read authz cofiguration. Skip this error.", "skip_error", err)
		} else {
			// watch authz json file for changes
			viper.WatchConfig()
			viper.OnConfigChange(func(e fsnotify.Event) {
				globalConfig.SpiffeID = viper.GetStringSlice("quicsec.authz_rules")
			})
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

		// log http requests into file
		if globalConfig.LogAccessOutputFile != "" {
			globalConfig.LogAccessOutputFileFlag = true
		} else {
			globalConfig.LogAccessOutputFileFlag = false
		}

		// skip CA verify
		if globalConfig.InsecureSkipVerify == 1 {
			globalConfig.InsecureSkipVerifyFlag = true
		} else {
			globalConfig.InsecureSkipVerifyFlag = false
		}

		// mTLS
		if globalConfig.MTlsEnable == 1 {
			globalConfig.MTlsEnableFlag = true
		} else {
			globalConfig.MTlsEnableFlag = false
		}

		confLogger.V(log.DebugLevel).Info("all configuration loaded")

	})

	return globalConfig
}
