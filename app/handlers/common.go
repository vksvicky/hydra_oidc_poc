/*
 Copyright 2020, 2021 Jan Dittberner


 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	log "github.com/sirupsen/logrus"

	"git.cacert.org/oidc_login/app/services"
	"git.cacert.org/oidc_login/common/models"
	commonServices "git.cacert.org/oidc_login/common/services"
)

const sessionName = "resource_session"

func Authenticate(ctx context.Context, logger *log.Logger, clientId string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := services.GetSessionStore().Get(r, sessionName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, ok := session.Values[sessionKeyIdToken]; ok {
				next.ServeHTTP(w, r)
				return
			}
			session.Values[sessionRedirectTarget] = r.URL.String()
			if err = session.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var authUrl *url.URL
			if authUrl, err = url.Parse(commonServices.GetOAuth2Config(ctx).Endpoint.AuthURL); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			queryValues := authUrl.Query()
			queryValues.Set("client_id", clientId)
			queryValues.Set("response_type", "code")
			queryValues.Set("scope", "openid offline_access profile email")
			queryValues.Set("state", base64.URLEncoding.EncodeToString(commonServices.GenerateKey(8)))
			queryValues.Set("claims", getRequestedClaims(logger))
			authUrl.RawQuery = queryValues.Encode()

			w.Header().Set("Location", authUrl.String())
			w.WriteHeader(http.StatusFound)
		})
	}
}

func getRequestedClaims(logger *log.Logger) string {
	claims := make(models.OIDCClaimsRequest)
	claims["userinfo"] = make(models.ClaimElement)
	essentialItem := make(models.IndividualClaimRequest)
	essentialItem["essential"] = true
	claims["userinfo"]["https://cacert.localhost/groups"] = &essentialItem

	target := make([]byte, 0)
	buf := bytes.NewBuffer(target)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(claims); err != nil {
		logger.Warnf("could not encode claims request parameter: %v", err)
	}
	return buf.String()
}

func ParseIdToken(token string, keySet *jwk.Set) (openid.Token, error) {
	if parsedIdToken, err := jwt.ParseString(token, jwt.WithKeySet(keySet), jwt.WithOpenIDClaims()); err != nil {
		return nil, err
	} else {
		return parsedIdToken.(openid.Token), nil
	}

}
