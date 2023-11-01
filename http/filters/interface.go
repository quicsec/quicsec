package filters

import "net/http"

type Filters interface {
	Execute(http.ResponseWriter, *http.Request, http.HandlerFunc) error
}