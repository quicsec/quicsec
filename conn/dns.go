package conn

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

type RecordCache struct {
	Priority 	int
	Addr 		string
	Duration	float32
}

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
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	// Create a query
	query := dns.Msg{}

	query.SetQuestion(fqdn, dnsType)

	// Send the query to a DNS resolver
	res, _, err := client.Exchange(&query, net.JoinHostPort(config.Servers[0], "53"))

	if err != nil {
		return nil, fmt.Errorf("Error querying DNS:", err)
	}

	// return the response
	if res.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("Dns resolution for %s failed", domain)
	}

	return res, nil
}

func parseHttpsRecord(dnsMsg *dns.Msg) (map[int]string, uint32) {
	var upstreams = make(map[int]string)
	var ttl uint32

	if dnsMsg != nil {
		re := regexp.MustCompile(`\[(\S+)\s+(\S+)\s+(\S+)\]`)
		for _, answer := range dnsMsg.Answer {
			if srv, ok := answer.(*dns.HTTPS); ok {
				ttl = srv.Header().Ttl
				matches := re.FindStringSubmatch(fmt.Sprintf("%s", srv.Value))

				if len(matches) == 4 {
					ip := matches[3]
					port := matches[2]
					addr := fmt.Sprintf("%s:%s", ip, port)

					upstreams[int(srv.Priority)] = addr
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

func takeFirst(ups map[int]string) string {
	// Get the map keys and sort them
	keys := make([]int, 0, len(ups))
	for k := range ups {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	return ups[keys[0]]
}

func GetPriorEpAddress(domain string) string {
	msg, err := lookUp(domain, dns.TypeHTTPS)

	if err != nil {
		return ""
	}

	ips, _ := parseHttpsRecord(msg)

	return takeFirst(ips)
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
		return nil, fmt.Errorf("Failed to  parse HTTPS record");
	}

	keys := make([]int, 0, len(ups))
	for k := range ups {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	var endpoints []string

	for _, k := range keys {
		endpoints = append(endpoints, ups[k])
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