package config

type Loader interface {
	Load()
	GetConfig() *Config
}
