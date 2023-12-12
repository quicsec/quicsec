package filters

import (
	"fmt"
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
			// http.Error(w, err.Error(), http.StatusForbidden)
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html")
			errorHtml := fmt.Sprintf(`
                <html>
                    <head><title>QUICSEC Error</title></head>
                    <body>
                        <h1>Forbidden</h1>
                        <p>Sorry, the filter chain has identified unauthorized operation.</p>
                        <p>Error: %s</p>
                    </body>
                </html>
            `, err.Error())
			w.Write([]byte(errorHtml))
			return
		}
	}
	next(w, r)
}
