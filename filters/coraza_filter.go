package filters

import (
	"fmt"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/operations/log"
)

type CorazaFilter struct {
	Waf coraza.WAF
}

func NewCorazaFilter(config string) (*CorazaFilter, error) {
	waf, err := coraza.NewWAF(
			coraza.NewWAFConfig().
				WithErrorCallback(logError).
				WithDirectivesFromFile(config),
	)
	if err != nil {
		return nil, err
	}

	return  &CorazaFilter{Waf: waf},  nil
}

func (c *CorazaFilter) loadWafConfig(id RequestIdentity) error {
	var directives string
	var wafConfig *config.WafConfig

	if id.Class == UNK_IDENTITY || id.Class == NO_IDENTITY {
		wafConfig = config.GetWafConfig("*")
	} else {
		wafConfig = config.GetWafConfig(id.Spiffeid)
	}

	if wafConfig != nil {
		corazaConfig := wafConfig.Coraza
		for _, directive := range corazaConfig {
			directives += directive + "\n"
		}
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectives(directives),
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
				return fmt.Errorf("blocked by WAAP/WAF:Unauthorized identity")
		}
	}

	return nil
}

func logError(mr types.MatchedRule) {
	filterLogger := log.LoggerLgr.WithName("coraza-filter")
	msg := mr.ErrorLog()
	filterLogger.V(log.DebugLevel).Info("coraza-action", "severity:", mr.Rule().Severity(), "msg:", msg)
}