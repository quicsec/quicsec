package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/quicsec/quicsec/spiffeid"
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
	Local    LocalConfigs
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
	Method   string `mapstructure:"method"`
	CaPath   string `mapstructure:"ca_path"`
	KeyPath  string `mapstructure:"key_path"`
	CertPath string `mapstructure:"cert_path"`
}

type SecurityConfigs struct {
	Mtls MtlsConfig
}

type MtlsConfig struct {
	Enable          bool
	InsecSkipVerify bool `mapstructure:"insec_skip_verify"`
	Authz           AuthzConfigs
}

type AuthzConfigs struct {
	SpiffeID    map[string]bool
	defaultFlag bool
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

// AuthzConfig struct to parse the authz json file
type AuthzConfig struct {
	Quicsec AuthzQuicsecConfig `json:"quicsec"`
}

type AuthzQuicsecConfig struct {
	AuthzRules []string `json:"authz_rules"`
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

func GetCertsMethod() string {
	return globalConfig.Certs.Method
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

func GetLastAuthRules() (map[string]bool, bool) {
	return globalConfig.Security.Mtls.Authz.SpiffeID,
		globalConfig.Security.Mtls.Authz.defaultFlag
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

func SetLastAuthRules(spiffeURI map[string]bool, df bool) {
	globalConfig.Security.Mtls.Authz.SpiffeID = spiffeURI
	globalConfig.Security.Mtls.Authz.defaultFlag = df

}

func GetIdentity() spiffeid.ID {
	return globalConfig.Local.Identity
}

func SetIdentity(id spiffeid.ID) {
	globalConfig.Local.Identity = id
}

func GetServerSideFlag() bool {
	return globalConfig.Local.ServerSideFlag
}

func SetServerSideFlag(f bool) {
	globalConfig.Local.ServerSideFlag = f
}

func GetLocalOnlyH1() bool {
	return globalConfig.Local.H1Only
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

	fmt.Printf("Cert method:%s\n", c.Certs.Method)
	fmt.Printf("CAPath:%s\n", c.Certs.CaPath)
	fmt.Printf("KeyPath:%s\n", c.Certs.KeyPath)
	fmt.Printf("CertPath:%s\n", c.Certs.CertPath)

	fmt.Printf("MtlsEnable:%t\n", c.Security.Mtls.Enable)
	fmt.Printf("InsecureSkipVerify:%t\n", c.Security.Mtls.InsecSkipVerify)
	fmt.Printf("Authz:\n")
	for key, df := range c.Security.Mtls.Authz.SpiffeID {
		fmt.Printf("\t%s:%t\n", key, df)
	}
	fmt.Println("")

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
		viper.SetDefault("log.debug", false)                       // QUICSEC_LOG_DEBUG
		viper.SetDefault("log.path", "")                           // QUICSEC_LOG_PATH
		viper.SetDefault("http.access.path", "")                   // QUICSEC_HTTP_ACCESS_PATH
		viper.SetDefault("quic.debug.secret_path", "")             // QUICSEC_QUIC_DEBUG_SECRET_PATH
		viper.SetDefault("quic.debug.qlog_path", "./qlog/")        // QUICSEC_QUIC_DEBUG_QLOG_PATH
		viper.SetDefault("metrics.enable", true)                   // QUICSEC_METRICS_ENABLE
		viper.SetDefault("metrics.bind_port", 9090)                // QUICSEC_METRICS_BIND_PORT
		viper.SetDefault("certs.method", "disk")                   // QUICSEC_CERTS_METHOD (disk|aws)
		viper.SetDefault("certs.ca_path", "certs/ca.pem")          // QUICSEC_CERTS_CA_PATH
		viper.SetDefault("certs.key_path", "certs/cert.key")       // QUICSEC_CERTS_KEY_PATH
		viper.SetDefault("certs.cert_path", "certs/cert.pem")      // QUICSEC_CERTS_CERT_PATH
		viper.SetDefault("security.mtls.insec_skip_verify", false) // QUICSEC_SECURITY_MTLS_INSEC_SKIP_VERIFY
		viper.SetDefault("local.h1only", false)                    // QUICSEC_LOCAL_H1ONLY

		if err := viper.ReadInConfig(); err != nil {
			fmt.Println("config: error reading config file: " + err.Error())
		} else {
			// watch authz json file for changes
			viper.WatchConfig()
			viper.OnConfigChange(func(e fsnotify.Event) {
				loadSecurityConfig()
				confLogger.V(log.DebugLevel).Info("Security config has changed...")
				// globalConfig.ShowConfig()
			})
		}

		loadSecurityConfig()

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

		globalConfig.ShowConfig()

	})

	return globalConfig
}

func loadSecurityConfig() {
	var confLogger logr.Logger
	localIPs, err := getCurrentIPs()
	if err != nil {
		panic("failed to get ips from netwrok interfaces.")
	}

	if viper.IsSet("qm_service_conf") {
		rawConfigs := viper.Get("qm_service_conf")
		if configs, ok := rawConfigs.([]interface{}); ok {
			spiffeIDs := make(map[string]bool)
			for _, conf := range configs {
				c := conf.(map[string]interface{})
				if serverInstanceKey, exists := c["server_instance_key"].(string); exists {
					kIp := net.ParseIP(serverInstanceKey)
					if kIp == nil {
						panic("failed to parse server_instance_key as an IP adrress format")
					}
					if matchIP(kIp, localIPs) {
						if policies, exists := c["policy"].(map[string]interface{}); exists {
							defaultFlag := false
							for key, policyVal := range policies {
								policyDetails := policyVal.(map[string]interface{})
								authzVal, ok := policyDetails["authz"].(string)
								allowFlag := false
								if ok && authzVal == "allow" {
									allowFlag = true
								}
								// strict rules
								if strings.HasPrefix(key, "spiffe://") {
									spiffeIDs[key] = allowFlag
								}
								// default rule
								if strings.HasPrefix(key, "*") {
									defaultFlag = allowFlag
								}

							}
							SetLastAuthRules(spiffeIDs, defaultFlag)
						}

						if clientCertValue, exists := c["client_cert"].(bool); exists {
							SetMtlsEnable(clientCertValue)
						} else {
							confLogger.V(log.DebugLevel).Info("client_cert key not found. Keeping it disable...")
							SetMtlsEnable(false)
						}
					}
				}
			}
		} else {
			panic("Unexpected type for 'qm_service_conf'")
		}
	} else {
		panic("qm_service_conf' key not found in config")
	}
}

func getCurrentIPs() ([]net.IP, error) {
	var ips []net.IP

	// Fetch all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addresses {
			switch v := addr.(type) {
			case *net.IPNet:
				ips = append(ips, v.IP)
			case *net.IPAddr:
				ips = append(ips, v.IP)
			}
		}
	}

	return ips, nil
}

func matchIP(ip net.IP, ips []net.IP) bool {
	for _, i := range ips {
		if ip.Equal(i) {
			return true
		}
	}
	return false
}
