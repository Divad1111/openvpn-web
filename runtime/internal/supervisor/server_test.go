package supervisor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUninitializedAndNoMutations(t *testing.T) {
	h := Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "UNINITIALIZED") {
		t.Fatalf("unexpected: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/start", nil))
	if w.Code < 400 {
		t.Fatal("mutation should be denied")
	}
}
