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
	"net/http"
	"time"

	"github.com/ory/hydra-client-go/client/admin"
	log "github.com/sirupsen/logrus"
)

type logoutHandler struct {
	adminClient *admin.Client
	logger      *log.Logger
}

func (h *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("logout_challenge")
	h.logger.Debugf("received challenge %s\n", challenge)

	logoutRequest, err := h.adminClient.GetLogoutRequest(
		admin.NewGetLogoutRequestParams().WithLogoutChallenge(challenge).WithTimeout(time.Second * 10))
	if err != nil {
		h.logger.Errorf("error getting logout requests: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	h.logger.Debugf("received logout request: %#v", logoutRequest.Payload)

	acceptLogoutRequest, err := h.adminClient.AcceptLogoutRequest(
		admin.NewAcceptLogoutRequestParams().WithLogoutChallenge(challenge))
	if err != nil {
		h.logger.Errorf("error accepting logout: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	w.Header().Set("Location", *acceptLogoutRequest.GetPayload().RedirectTo)
	w.WriteHeader(http.StatusFound)
}

func NewLogoutHandler(ctx context.Context, logger *log.Logger) *logoutHandler {
	return &logoutHandler{
		logger:      logger,
		adminClient: ctx.Value(CtxAdminClient).(*admin.Client),
	}
}

type logoutSuccessHandler struct {
}

func (l *logoutSuccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	panic("implement me")
}

func NewLogoutSuccessHandler() *logoutSuccessHandler {
	return &logoutSuccessHandler{}
}
