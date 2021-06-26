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
	"net/http"

	"github.com/sirupsen/logrus"

	"git.cacert.org/oidc_login/app/services"
)

type afterLogoutHandler struct {
	logger *logrus.Logger
}

func (h *afterLogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, err := services.GetSessionStore().Get(r, sessionName)
	if err != nil {
		h.logger.Errorf("could not get session: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Options.MaxAge = -1
	if err = session.Save(r, w); err != nil {
		h.logger.Errorf("could not save session: %v", err)
	}

	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusFound)
}

func NewAfterLogoutHandler(logger *logrus.Logger) *afterLogoutHandler {
	return &afterLogoutHandler{logger: logger}
}
