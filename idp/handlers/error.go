package handlers

import (
	"fmt"
	"net/http"
)

type errorHandler struct {
}

func (e *errorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, `
didumm %#v
`, r.URL.Query())
}

func NewErrorHandler() *errorHandler {
	return &errorHandler{}
}
