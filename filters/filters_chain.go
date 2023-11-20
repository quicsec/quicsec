package filters

import (
	"fmt"

	"github.com/quicsec/quicsec/config"
)

func GetConfiguredFilters(id RequestIdentity) ([]Filter, error) {
	var filters []Filter
	var filtersConfig []string

	if id.Class == UNK_IDENTITY || id.Class == NO_IDENTITY {
		filtersConfig = config.GetFiltersChain("*")
	} else {
		filtersConfig = config.GetFiltersChain(id.Spiffeid)
	}

	if len(filtersConfig) <= 0 {
		return nil, fmt.Errorf("failed to retrieve filters for indentity %s", id.Spiffeid)
	}

	for _, filter := range filtersConfig {
		if filter == "waf" {
			filters = append(filters, &CorazaFilter{})
		}
		if filter == "ext_auth" {
			filters = append(filters, &ExtAuthFilter{})
		}
		if filter == "oauth2" {
			filters = append(filters, &Oauth2Filter{})
		}
	}
	return filters, nil
}