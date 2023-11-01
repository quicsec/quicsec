package filters

import (
	"fmt"
	"log"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type CorazaFilter struct {
	Waf coraza.WAF
}

func NewCorazaFilter(config string) *CorazaFilter {
	waf, err := coraza.NewWAF(
			coraza.NewWAFConfig().
				WithErrorCallback(logError).
				WithDirectivesFromFile(config),
	)
	if err != nil {
		log.Fatal(err)
	}

	return  &CorazaFilter{Waf: waf}
}

func (c *CorazaFilter) Execute(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error {
	
	tx := c.Waf.NewTransaction()

	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)
	tx.ProcessRequestHeaders()

	if it := tx.Interruption();it != nil {
		switch it.Action {
			case "deny":
				http.Error(w, "blocked by WAF", http.StatusForbidden)
				return fmt.Errorf("blocked by WAF")
		}
	}

	return nil
}

func logError(error types.MatchedRule) {
	msg := error.ErrorLog()
	fmt.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
}