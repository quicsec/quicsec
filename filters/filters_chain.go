package filters

import (
	"fmt"

	"github.com/quicsec/quicsec/config"
)

func GetConfiguredFilters(id RequestIdentity) ([]Filter, error) {
	var filters []Filter

	filtersCfg := config.GetFiltersChain(id.Spiffeid)
	if len(filtersCfg) <= 0 {
		return nil, fmt.Errorf("failed to retrieve filters for indentity %s", id.Spiffeid)
	}
	for _, filter := range filtersCfg {
		if filter == "waf" {
			filters = append(filters, &CorazaFilter{})
		}
		if filter == "ext_auth" {
			filters = append(filters, &ExtAuthFilter{})
		}
	}
	return filters, nil
}