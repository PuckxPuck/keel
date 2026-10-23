package httpx

import "net/http"

// recorder remembers what was written so middleware can log it and Recover knows whether headers are out.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and the deadlines of the real writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *recorder) written() bool { return r.status != 0 }

func record(w http.ResponseWriter) *recorder {
	if rec, ok := w.(*recorder); ok {
		return rec
	}
	return &recorder{ResponseWriter: w}
}
