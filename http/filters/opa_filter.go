// quicsec/http/filters/ext_auth_filter.go
package filters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	. "github.com/quicsec/quicsec/http"
)

type ExtAuthFilter struct {
	opaURL string
}

func NewExtAuthFilter(opaURL string) *ExtAuthFilter {
	return &ExtAuthFilter{opaURL: opaURL}
}

func (e *ExtAuthFilter) loadOPAConfig(id RequestIdentity) error {
	var policyUrl string
	switch id.Class {
		case NO_IDENTITY:
			policyUrl = os.Getenv("QUICSEC_OPA_NO_ID_POLICY")
		case UNK_IDENTITY:
			policyUrl = os.Getenv("QUICSEC_OPA_UKN_ID_POLICY")
		case KNW_IDENTITY:
			policyUrl = os.Getenv("QUICSEC_OPA_KNW_ID_POLICY")
		default:
			policyUrl = os.Getenv("QUICSEC_OPA_DEFAULT_POLICY")
	}

	if policyUrl == "" {
		fmt.Println("no OPA policy found for identiy class:", id.Class.String(), "loading default OPA policy")
		policyUrl = os.Getenv("QUICSEC_OPA_DEFAULT_POLICY")

		if policyUrl == "" {
			return fmt.Errorf("failed to load default OPA rules. The env variable QUICSEC_OPA_DEFAULT_POLICY must be configured")
		}
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
