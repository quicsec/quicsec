package qhttp

import (
	"net/http"

	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/identity"
)

type IdentityClass int

type RequestIdentity struct {
	Class    IdentityClass
	Spiffeid string
}

const (
	NO_IDENTITY IdentityClass = iota
	UNK_IDENTITY
	KNW_IDENTITY
)

func (ic IdentityClass) String() string {
	names := []string{"NO_IDENTITY", "UKN_IDENTITY", "KNW_IDENTITY"}
	if ic < NO_IDENTITY || ic > KNW_IDENTITY {
		return "CLASS_UNKNOWN"
	}
	return names[ic]
}

func GetRequestIdentity(r *http.Request) RequestIdentity {
	if len(r.TLS.PeerCertificates) > 0 {
		pCert := r.TLS.PeerCertificates[0] // we take only the first

		reqIdentity, err := identity.IDFromCert(pCert)
		if err != nil {
			return RequestIdentity{
				Class:    NO_IDENTITY,
				Spiffeid: "",
			}
		}
		knowId := false
		kIds := config.GetAllowedIdentities()

		for id := range kIds {
			if reqIdentity.String() == id {
				knowId = true
				break
			}
		}

		if knowId {
			return RequestIdentity{
				Class:    KNW_IDENTITY,
				Spiffeid: reqIdentity.String(),
			}
		} else {
			return RequestIdentity{
				Class:    UNK_IDENTITY,
				Spiffeid: reqIdentity.String(),
			}
		}
	}

	return RequestIdentity{
		Class:    NO_IDENTITY,
		Spiffeid: "",
	}
}
