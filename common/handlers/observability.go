package handlers

import (
	"context"
	"net/http"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

type key int

const (
	requestIdKey key = iota
)

func Logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestId, ok := r.Context().Value(requestIdKey).(string)
				if !ok {
					requestId = "unknown"
				}
				logger.Infoln(requestId, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func Tracing(nextRequestId func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestId := r.Header.Get("X-Request-Id")
			if requestId == "" {
				requestId = nextRequestId()
			}
			ctx := context.WithValue(r.Context(), requestIdKey, requestId)
			w.Header().Set("X-Request-Id", requestId)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

var Healthy int32

func NewHealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&Healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}
