// +build linux
package conn

import (
	"github.com/miekg/dns"
)

func dnsClientConfig() (*dns.ClientConfig, error) {
	return dns.ClientConfigFromFile("/etc/resolv.conf")
}

