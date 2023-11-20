package config

func parseWafConfig(wafData map[string]interface{}) (WafConfig, error) {
	var wafConfigParsed WafConfig
	if corazaRules, ok := wafData["coraza"].([]interface{}); ok {
		for _, rule := range corazaRules {
			if wafRule, ok := rule.(string); ok {
				wafConfigParsed.Coraza = append(wafConfigParsed.Coraza, wafRule)
			}
		}
	}
	return wafConfigParsed, nil
}

func parseExtAuthConfig(extAuthData map[string]interface{}) (OpaConfig, error) {
	var opaConfigParsed OpaConfig
	if opaConfig, ok := extAuthData["opa"].(map[string]interface{}); ok {
		if url, ok := opaConfig["url"].(string); ok {
			opaConfigParsed.Url = url
		}
		if auth, ok := opaConfig["auth"].(string); ok {
			opaConfigParsed.Auth = auth
		}
		if passJwt, ok := opaConfig["pass_jwt_claims"].(string); ok {
			opaConfigParsed.PassJwtClaims = passJwt
		}
		if passSvcId, ok := opaConfig["pass_svc_identity"].(string); ok {
			opaConfigParsed.PassServiceIdentity = passSvcId
		}
		if passCliId, ok := opaConfig["pass_cli_identity"].(string); ok {
			opaConfigParsed.PassClientIdentity = passCliId
		}

	}
	return opaConfigParsed, nil
}

func parseOAuth2Config(oAuth2Data map[string]interface{}) (Oauth2Config, error) {
	var oAuth2ConfigParsed Oauth2Config

	if cId, ok := oAuth2Data["client_id"].(string); ok {
		oAuth2ConfigParsed.ClientId = cId
	}
	if cS, ok := oAuth2Data["client_secret"].(string); ok {
		oAuth2ConfigParsed.ClientSecret = cS
	}
	if azEp, ok := oAuth2Data["authz_endpoint"].(string); ok {
		oAuth2ConfigParsed.AuthzEp = azEp
	}
	if tEp, ok := oAuth2Data["token_endpoint"].(string); ok {
		oAuth2ConfigParsed.TokenEp = tEp
	}
	if rUrl, ok := oAuth2Data["redirect_url"].(string); ok {
		oAuth2ConfigParsed.RedirectURL = rUrl
	}
	if s, ok := oAuth2Data["scopes"].([]string); ok {
		oAuth2ConfigParsed.Scopes = s
	}

	return oAuth2ConfigParsed, nil
}
