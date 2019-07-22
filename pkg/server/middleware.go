package server

// Logging middleware inspired by github.com/urfave/negroni

import (
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

func (rw *responseWriter) Status() int {
	return rw.status
}

func (rw *responseWriter) WriteHeader(s int) {
	rw.status = s
	rw.ResponseWriter.WriteHeader(s)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}

	return rw.ResponseWriter.Write(data)
}

var _ http.ResponseWriter = &responseWriter{}
var _ http.ResponseWriter = &responseWriterHijacker{}
var _ http.Hijacker = &responseWriterHijacker{}

// ResponseStatusWriter wraps http.ResponseWriter to save HTTP status code
type ResponseStatusWriter interface {
	http.ResponseWriter
	Status() int
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

type responseWriterHijacker struct {
	*responseWriter
	http.Hijacker
}

func NewResponseStatusWriter(w http.ResponseWriter) ResponseStatusWriter {
	ret := &responseWriter{
		ResponseWriter: w,
	}

	if h, ok := w.(http.Hijacker); ok {
		return &responseWriterHijacker{
			responseWriter: ret,
			Hijacker:       h,
		}
	}

	return ret
}

// Logging is a logrus-enabled logging middleware
type Logging struct {
	Logger *log.Logger
}

func (l *Logging) log() *log.Logger {
	if l.Logger != nil {
		return l.Logger
	}
	return log.StandardLogger()
}

// Handler wraps provided http.Handler with middleware
func (l *Logging) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timestamp := time.Now()

		rw := NewResponseStatusWriter(w)
		h.ServeHTTP(rw, r)

		fields := log.Fields{
			"start_time": timestamp.Format(time.RFC3339),
			"duration":   time.Since(timestamp),
			"status":     rw.Status(),
			"hostname":   r.Host,
			"method":     r.Method,
			"path":       r.URL.Path,
		}

		l.log().WithFields(fields).Println(r.Method + " " + r.URL.Path)
	})
}
