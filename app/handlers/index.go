package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"git.cacert.org/oidc_login/app/services"
)

type indexHandler struct {
	logoutUrl  string
	serverAddr string
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
	writer.WriteHeader(http.StatusOK)

	page, err := template.New("").Parse(`
<!DOCTYPE html>
<html lang="en">
<head><title>Auth test</title></head>
<body>
<h1>Hello {{ .User }}</h1>
<p>This is an authorization protected resource</p>
<a href="{{ .LogoutURL }}">Logout</a>
</body>
</html>
`)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
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
	var user string
	var ok bool
	if user, ok = session.Values[sessionKeyUsername].(string); ok {

	}
	if idToken, ok := session.Values[sessionKeyIdToken].(string); ok {
		logoutUrl.RawQuery = url.Values{
			"id_token_hint":            []string{idToken},
			"post_logout_redirect_uri": []string{fmt.Sprintf("https://%s/after-logout", h.serverAddr)},
		}.Encode()
	}

	writer.Header().Add("Content-Type", "text/html")
	err = page.Execute(writer, map[string]interface{}{
		"User":      user,
		"LogoutURL": logoutUrl.String(),
	})
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func NewIndexHandler(logoutUrl string, serverAddr string) *indexHandler {
	return &indexHandler{logoutUrl: logoutUrl, serverAddr: serverAddr}
}
