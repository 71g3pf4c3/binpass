package v1

import (
	"context"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorHandler customises gateway HTTP status mapping so that a manifest CAS
// conflict (FailedPrecondition) surfaces as 412 Precondition Failed, and a
// quota/size breach (ResourceExhausted) as 429, matching the API contract.
func errorHandler(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	st := status.Convert(err)
	switch st.Code() {
	case codes.FailedPrecondition:
		overrideStatus(ctx, mux, m, w, r, err, http.StatusPreconditionFailed)
	case codes.ResourceExhausted:
		overrideStatus(ctx, mux, m, w, r, err, http.StatusTooManyRequests)
	default:
		runtime.DefaultHTTPErrorHandler(ctx, mux, m, w, r, err)
	}
}

// overrideStatus renders the standard gateway error body but forces a
// specific HTTP status code on the response.
func overrideStatus(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error, code int) {
	overrideWriter := &statusWriter{ResponseWriter: w, code: code}
	runtime.DefaultHTTPErrorHandler(ctx, mux, m, overrideWriter, r, err)
}

// statusWriter forces a specific status code on the first WriteHeader call.
type statusWriter struct {
	http.ResponseWriter
	// code is the status code to force.
	code int
	// wrote records whether the header was already written.
	wrote bool
}

// WriteHeader forces the configured code once.
func (s *statusWriter) WriteHeader(int) {
	if s.wrote {
		return
	}
	s.wrote = true
	s.ResponseWriter.WriteHeader(s.code)
}

// Write ensures the forced status is emitted before the body.
func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(s.code)
	}
	return s.ResponseWriter.Write(b)
}
