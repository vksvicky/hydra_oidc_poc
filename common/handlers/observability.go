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
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

type key int

const (
	requestIdKey key = iota
)

type statusCodeInterceptor struct {
	http.ResponseWriter
	code  int
	count int
}

func (sci *statusCodeInterceptor) WriteHeader(code int) {
	sci.code = code
	sci.ResponseWriter.WriteHeader(code)
}

func (sci *statusCodeInterceptor) Write(content []byte) (int, error) {
	count, err := sci.ResponseWriter.Write(content)
	sci.count += count
	return count, err
}

func Logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			interceptor := &statusCodeInterceptor{w, http.StatusOK, 0}
			defer func() {
				requestId, ok := r.Context().Value(requestIdKey).(string)
				if !ok {
					requestId = "unknown"
				}
				logger.Infof(
					"%s %s \"%s %s\" %d %d \"%s\"",
					requestId,
					r.RemoteAddr,
					r.Method,
					r.URL.Path,
					interceptor.code,
					interceptor.count,
					r.UserAgent(),
				)
			}()
			next.ServeHTTP(interceptor, r)
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
