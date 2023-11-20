package filters

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/quicsec/quicsec/config"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type Oauth2Filter struct {
}

var (
	provider *oidc.Provider
	oauth2Cfg *oauth2.Config
	oauth2FilterCfg *config.Oauth2Config
)

func (j *Oauth2Filter) Execute(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) error {
	err := loadOauth2Config(GetRequestIdentity(r))
	if err != nil {
		return err
	}
	//[TODO] like envoy we should expose this to the config (matcher)
	if  r.URL.Path  == "/callback" {
		callbackHandler(w,r)
		return nil
	}

	if strings.Contains(oauth2Cfg.Endpoint.AuthURL, r.Host) {
		return nil
	}

	tokenStr := extractToken(r)
	if tokenStr == "" {
		cookie, err := r.Cookie("auth-token")
		if err != nil {
			redirectToIdentityProvider(w, r)
			return nil
		} else {
			tokenStr = cookie.Value
		}
	}

	token, err := validateToken(tokenStr)
	if err != nil {
		http.Error(w, "Error validating token: "+err.Error(), http.StatusUnauthorized)
		return err
	}

	if !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return fmt.Errorf("invalid token.Not authorized")
	}

	//Authorized
	return nil
}

func loadOauth2Config(id RequestIdentity) error {
	var err error

	if id.Class == UNK_IDENTITY || id.Class == NO_IDENTITY {
		oauth2FilterCfg = config.GetOauth2Config("*")
	} else {
		oauth2FilterCfg = config.GetOauth2Config(id.Spiffeid)
	}

	provider, err = oidc.NewProvider(context.Background(), oauth2FilterCfg.AuthzEp)
	if err != nil {
		return err
	}

	oauth2Cfg = &oauth2.Config{
		ClientID:     oauth2FilterCfg.ClientId,
		ClientSecret: oauth2FilterCfg.ClientSecret,
		RedirectURL:  oauth2FilterCfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{"openid", "profile", "email"},
	}

	return nil
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func validateToken(tokenStr string) (*jwt.Token, error) {
	set, err := jwk.Fetch(context.Background(), oauth2FilterCfg.AuthzEp + ".well-known/jwks.json")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKs: %v", err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("expecting JWT header to have string kid")
		}

		key, ok := set.LookupKeyID(keyID)
		if !ok {
			return nil, fmt.Errorf("unable to find key %q", keyID)
		}

		var publicKey interface{}
		if err := key.Raw(&publicKey); err != nil {
			return nil, fmt.Errorf("unable to get raw key: %v", err)
		}

		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//[TODO] when auth code flow the audience is the clientID
		if aud, ok := claims["aud"].(string); !ok || aud != oauth2FilterCfg.ClientId {
			return nil, fmt.Errorf("invalid audience")
		}
		if iss, ok := claims["iss"].(string); !ok || iss != oauth2FilterCfg.AuthzEp {
			return nil, fmt.Errorf("invalid issuer")
		}
	} else {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func redirectToIdentityProvider(w http.ResponseWriter, r *http.Request) {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	//[TODO] we should manage the state code to avoid CSRF
	state := rand.Intn(0xffffffffffffff)
	redirectTo := oauth2Cfg.AuthCodeURL(strconv.Itoa(state))
	http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    oauth2Token, err := oauth2Cfg.Exchange(context.Background(), r.URL.Query().Get("code"))
    if err != nil {
        http.Error(w, "failed to exchange access code by a token", http.StatusInternalServerError)
        return
    }

    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
    if !ok {
        http.Error(w, "failed to parse exchanged token", http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:  "auth-token",
        Value: rawIDToken,
        Path:  "/",
    })
	//[TODO] redirect to original destination
    http.Redirect(w, r, "/", http.StatusSeeOther)
}
