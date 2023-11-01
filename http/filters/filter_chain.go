package filters

import (
	"net/http"
)

type FilterChain struct {
	Filters []Filters
}

func (f *FilterChain) Apply(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	for _,  filter := range f.Filters {
		if err := filter.Execute(w,r, next); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	next(w, r)
}