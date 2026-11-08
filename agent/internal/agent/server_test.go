package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMutationsDeniedEvenInWriteMode(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := Server{WriteEnabled: enabled, RuntimeSocket: "/tmp/nowhere"}
		for _, path := range []string{"/v1/apply", "/v1/pki/revoke", "/v1/runtime/stop"} {
			r := httptest.NewRequest(http.MethodPost, path, nil)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatalf("mode=%v path=%s code=%d", enabled, path, w.Code)
			}
			if !enabled && w.Code != http.StatusLocked {
				t.Fatalf("want 423, got %d", w.Code)
			}
		}
	}
}
