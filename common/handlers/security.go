package handlers

import (
	"fmt"
	"net/http"
	"time"
)

func EnableHSTS() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d", int((time.Hour*24*180).Seconds())))
			next.ServeHTTP(w, r)
		})
	}
}
