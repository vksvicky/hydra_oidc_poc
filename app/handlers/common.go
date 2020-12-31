package handlers

import (
	"encoding/base64"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"git.cacert.org/oidc_login/app/services"
	commonServices "git.cacert.org/oidc_login/common/services"
)

const sessionName = "resource_session"

func Authenticate(oauth2Config *oauth2.Config, clientId string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := services.GetSessionStore().Get(r, sessionName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, ok := session.Values[sessionKeyUserId]; ok {
				next.ServeHTTP(w, r)
				return
			}
			session.Values[sessionRedirectTarget] = r.URL.String()
			if err = session.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var authUrl *url.URL
			if authUrl, err = url.Parse(oauth2Config.Endpoint.AuthURL); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			queryValues := authUrl.Query()
			queryValues.Set("client_id", clientId)
			queryValues.Set("response_type", "code")
			queryValues.Set("scope", "openid offline_access profile email")
			queryValues.Set("state", base64.URLEncoding.EncodeToString(commonServices.GenerateKey(8)))
			authUrl.RawQuery = queryValues.Encode()

			w.Header().Set("Location", authUrl.String())
			w.WriteHeader(http.StatusFound)
		})
	}
}
