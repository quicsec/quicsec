package filters

import (
	"fmt"
	"net/http"

	"github.com/quicsec/quicsec/operations/log"
)

type Filter interface {
	Execute(http.ResponseWriter, *http.Request, http.HandlerFunc) error
}

type FilterChain struct {
	Filters []Filter
}

func (f *FilterChain) Apply(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	var err error
	logger := log.LoggerLgr.WithName(log.ConstFilterChain)

	logger.V(log.DebugLevel).Info("applying filters to the chain")

	f.Filters, err = GetConfiguredFilters(GetRequestIdentity(r))
	if err != nil {
		logger.V(log.DebugLevel).Info("no filters configured for this deploy")
	 f.Filters = nil
	}

	for _,  filter := range f.Filters {
		if err := filter.Execute(w,r, next); err != nil {
			logger.V(log.DebugLevel).Info("request no authorized by filters.", " error", err)

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
