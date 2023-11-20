package filters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/quicsec/quicsec/config"
)

type ExtAuthFilter struct {
	opaURL string
}

func NewExtAuthFilter(opaURL string) (*ExtAuthFilter, error) {
	return &ExtAuthFilter{opaURL: opaURL}, nil
}

func (e *ExtAuthFilter) loadOPAConfig(id RequestIdentity) error {
	var policyUrl string
	var extAuthConfig *config.ExtAuthConfig

	if id.Class == UNK_IDENTITY || id.Class == NO_IDENTITY {
		extAuthConfig = config.GetExtAuthConfig("*")
	} else {
		extAuthConfig = config.GetExtAuthConfig(id.Spiffeid)
	}

	if extAuthConfig != nil {
		opaConfig := extAuthConfig.Opa
		if opaConfig.Url != "" {
			policyUrl = opaConfig.Url
		}
		// [TODO] we need a default rule or fallback here
	}

	e.opaURL = policyUrl
	return nil
}

func (e *ExtAuthFilter) Execute(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error {
	err := e.loadOPAConfig(GetRequestIdentity(r))
	if err != nil {
		return err
	}

	input := map[string]interface{}{
		"input": map[string]interface{}{
			"method": r.Method,
			"path":   r.URL.Path,
			// ... other relevant input
		},
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return err
	}

	resp, err := http.Post(e.opaURL, "application/json", bytes.NewBuffer(inputBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	resultMap, ok := result["result"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("error parsing OPA result map")
	}

	allowed, ok := resultMap["allow"].(bool)
	if !ok || !allowed {
		return fmt.Errorf("blocked by OPA")
	}

	return nil
}
