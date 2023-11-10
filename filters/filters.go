package filters

import (
	"net/http"
)

type Filter interface {
	Execute(http.ResponseWriter, *http.Request, http.HandlerFunc) error
}

type FilterChain struct {
	Filters []Filter
}

func (f *FilterChain) Apply(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	var err error

	f.Filters, err = GetConfiguredFilters(GetRequestIdentity(r))
	if err != nil {
	 f.Filters = nil
	}

	for _,  filter := range f.Filters {
		if err := filter.Execute(w,r, next); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	next(w, r)
}
