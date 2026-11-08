package engine

import (
	"strings"
	"testing"
)

func TestConfigAndRendering(t *testing.T) {
	c := Config{PublicHost: "vpn.example.com", VPNCIDR: "10.8.0.0/24", LANCIDR: "192.168.1.0/24", DNS: "192.168.1.1"}
	out, err := Render(c)
	if err != nil || !strings.Contains(out, `push "route 192.168.1.0 255.255.255.0"`) {
		t.Fatalf("render %s %v", out, err)
	}
	for _, bad := range []Config{{PublicHost: "x;cat /etc/passwd", VPNCIDR: c.VPNCIDR, LANCIDR: c.LANCIDR, DNS: c.DNS}, {PublicHost: c.PublicHost, VPNCIDR: c.LANCIDR, LANCIDR: c.LANCIDR, DNS: c.DNS}, {PublicHost: c.PublicHost, VPNCIDR: c.VPNCIDR, LANCIDR: c.LANCIDR, DNS: "x\nlog"}} {
		if ValidConfig(bad) == nil {
			t.Fatalf("invalid config accepted: %+v", bad)
		}
	}
}
