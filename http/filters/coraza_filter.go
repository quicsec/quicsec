package filters

import (
	"fmt"
	"log"
	"net/http"
	"os"

	. "github.com/quicsec/quicsec/http"

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
func (c *CorazaFilter) loadWafConfig(id RequestIdentity) error {
	var config string

	switch id.Class {
		case NO_IDENTITY:
			config = os.Getenv("QUICSEC_WAF_NO_ID_RULES")
		case UNK_IDENTITY:
			config = os.Getenv("QUICSEC_WAF_UKN_ID_RULES")
		case KNW_IDENTITY:
			config = os.Getenv("QUICSEC_WAF_KNW_ID_RULES")
		default:
			config = os.Getenv("QUICSEC_WAF_DEFAULT_RULES")
	}

	if config == "" {
		fmt.Println("no rules found for identiy class:", id.Class.String(), "loading default WAF rules")
		config = os.Getenv("QUICSEC_WAF_DEFAULT_RULES")

		if config == "" {
			return fmt.Errorf("failed to load default WAF rules. The env variable QUICSEC_WAF_DEFAULT_RULES must be configured")
		}
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectivesFromFile(config),
	)
	if err != nil {
		return err
	}
	
	c.Waf = waf

	return nil
}

func (c *CorazaFilter) Execute(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error {
	//we can chose the waf configuration given an identity
	err := c.loadWafConfig(GetRequestIdentity(r))
	if err != nil {
		return err
	}

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

func logError(mr types.MatchedRule) {
	msg := mr.ErrorLog()
	fmt.Printf("[logError][%s] %s\n", mr.Rule().Severity(), msg)
}