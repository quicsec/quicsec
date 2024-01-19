package conn

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

var rCache *cache.Cache
var rCacheLock sync.Mutex

func init() {
	rCache = cache.New(5*time.Minute, 10*time.Minute)
}

func lookUp(domain string, dnsType uint16) (*dns.Msg, error) {
	// Specify the HTTPS domain to lookup
	fqdn := dns.Fqdn(domain)

	// Create a DNS client
	client := dns.Client{}
	config, _ := dnsClientConfig()

	// Create a query
	query := dns.Msg{}

	query.SetQuestion(fqdn, dnsType)

	// Send the query to a DNS resolver
	res, _, err := client.Exchange(&query, net.JoinHostPort(config.Servers[0], "53"))

	if err != nil {
		return nil, fmt.Errorf("error querying DNS: %s", err.Error())
	}

	// return the response
	if res.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns resolution for %s failed with Rcode %d", domain, res.Rcode)
	}

	return res, nil
}

func tokenize(str, delimiter string) []string {
	return strings.Split(str, delimiter)
}

func parseHttpsRecord(dnsMsg *dns.Msg) (map[string]int, uint32) {
	var upstreams = make(map[string]int)
	var ttl uint32

	if dnsMsg != nil {
		re := regexp.MustCompile(`\[(\S+)\s+(\S+)\s+(\S+)\]`)
		for _, answer := range dnsMsg.Answer {
			if srv, ok := answer.(*dns.HTTPS); ok {
				ttl = srv.Header().Ttl
				matches := re.FindStringSubmatch(fmt.Sprintf("%s", srv.Value))

				if len(matches) == 4 {
					port := matches[2]
					ipv4Hint := matches[3]
					ips := tokenize(ipv4Hint, ",")
					for _, ip := range ips {
						addr := fmt.Sprintf("%s:%s", ip, port)
						upstreams[addr] = int(srv.Priority)
					}
				} else {
					fmt.Println("Invalid HTTPS valeu in RDATA")
				}

			}
		}
	}

	return upstreams, ttl
}

func parseARecord(dnsMsg *dns.Msg) string {
	var upstream string

	if dnsMsg  != nil{
		for _, answer := range dnsMsg.Answer {
			if a, ok := answer.(*dns.A); ok {
				upstream = a.A.String()
			}
		}
	}

	return upstream
}

func GetAllEpAddresses(domain string) ([]string, error) {
	rCacheLock.Lock()
	defer rCacheLock.Unlock()

	if cachedData, ok := rCache.Get(domain); ok {
		return cachedData.([]string), nil
	}

	msg, err := lookUp(domain, dns.TypeHTTPS)
	if err != nil {
		return nil, err
	}

	ups, ttl := parseHttpsRecord(msg)
	if len(ups) <= 0 {
		return nil, fmt.Errorf("failed to  parse HTTPS record");
	}

	var priorities []int
	for _, priority := range ups {
		priorities = append(priorities, priority)
	}
	sort.Ints(priorities)

	var endpoints []string
	addedAddrs := make(map[string]bool)
	for _, priority := range priorities {
		for address, addPriority := range ups {
			if addPriority == priority && !addedAddrs[address] {
				endpoints = append(endpoints, address)
				addedAddrs[address] = true
			}
		}
	}
	rCache.Set(domain, endpoints, time.Duration(ttl)*time.Second)

	return endpoints, nil
}

func GetEpAddress(domain string)(string, error) {
	msg, err := lookUp(domain, dns.TypeA)

	if err != nil {
		return "", err
	}

	return parseARecord(msg), nil
}
