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
