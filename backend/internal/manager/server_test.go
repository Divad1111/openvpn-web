package manager

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllWritesFailClosed(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := Server{WriteEnabled: enabled, AgentSocket: "/tmp/does-not-exist", WebDir: t.TempDir()}
		for _, path := range []string{"/api/v1/setup/admin", "/api/v1/clients", "/api/v1/vpn/start", "/api/v1/backups"} {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			res := httptest.NewRecorder()
			s.Handler().ServeHTTP(res, req)
			if res.Code < 400 {
				t.Fatalf("enabled=%v path=%s returned %d", enabled, path, res.Code)
			}
			if !enabled && res.Code != http.StatusLocked {
				t.Fatalf("expected 423 for read-only, got %d", res.Code)
			}
		}
	}
}
func TestFailClosedWithoutAgent(t *testing.T) {
	s := Server{WriteEnabled: true, AgentSocket: "/tmp/nonexistent", WebDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	var body struct {
		EffectiveWriteAllowed bool `json:"effectiveWriteAllowed"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.EffectiveWriteAllowed {
		t.Fatal("cannot allow writes when agent is unreachable")
	}
}
