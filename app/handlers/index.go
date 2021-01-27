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
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nicksnyder/go-i18n/v2/i18n"

	"git.cacert.org/oidc_login/app/services"
	commonServices "git.cacert.org/oidc_login/common/services"
)

type indexHandler struct {
	bundle         *i18n.Bundle
	indexTemplate  *template.Template
	keySet         *jwk.Set
	logoutUrl      string
	messageCatalog *commonServices.MessageCatalog
	serverAddr     string
}

func (h *indexHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	accept := request.Header.Get("Accept-Language")
	localizer := i18n.NewLocalizer(h.bundle, accept)
	writer.WriteHeader(http.StatusOK)

	session, err := services.GetSessionStore().Get(request, sessionName)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	logoutUrl, err := url.Parse(h.logoutUrl)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	var idToken string
	var ok bool
	if idToken, ok = session.Values[sessionKeyIdToken].(string); ok {
		logoutUrl.RawQuery = url.Values{
			"id_token_hint":            []string{idToken},
			"post_logout_redirect_uri": []string{fmt.Sprintf("https://%s/after-logout", h.serverAddr)},
		}.Encode()
	} else {
		return
	}

	oidcToken, err := ParseIdToken(idToken, h.keySet)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	writer.Header().Add("Content-Type", "text/html")
	err = h.indexTemplate.Lookup("base").Execute(writer, map[string]interface{}{
		"Title": h.messageCatalog.LookupMessage("IndexTitle", nil, localizer),
		"Greeting": h.messageCatalog.LookupMessage("IndexGreeting", map[string]interface{}{
			"User": oidcToken.Name(),
		}, localizer),
		"IntroductionText": h.messageCatalog.LookupMessage("IndexIntroductionText", nil, localizer),
		"LogoutLabel":      h.messageCatalog.LookupMessage("LogoutLabel", nil, localizer),
		"LogoutURL":        logoutUrl.String(),
	})
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func NewIndexHandler(ctx context.Context, serverAddr string) (*indexHandler, error) {
	indexTemplate, err := template.ParseFiles(
		"templates/app/base.gohtml", "templates/app/index.gohtml")
	if err != nil {
		return nil, err
	}
	return &indexHandler{
		bundle:         commonServices.GetI18nBundle(ctx),
		indexTemplate:  indexTemplate,
		keySet:         commonServices.GetJwkSet(ctx),
		logoutUrl:      commonServices.GetOidcConfig(ctx).EndSessionEndpoint,
		messageCatalog: commonServices.GetMessageCatalog(ctx),
		serverAddr:     serverAddr,
	}, nil
}
