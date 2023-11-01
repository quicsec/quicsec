// quicsec/http/filters/ext_auth_filter.go
package filters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type ExtAuthFilter struct {
	opaURL string
}

func NewExtAuthFilter(opaURL string) *ExtAuthFilter {
	return &ExtAuthFilter{opaURL: opaURL}
}

func (f *ExtAuthFilter) Execute(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error {
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

	resp, err := http.Post(f.opaURL, "application/json", bytes.NewBuffer(inputBytes))
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
