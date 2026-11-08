package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type NetworkPlan struct {
	VPNCIDR string `json:"vpnCIDR"`
	LANCIDR string `json:"lanCIDR"`
}

func loadNetwork(path string) (NetworkPlan, error) {
	var p NetworkPlan
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	if err = json.NewDecoder(f).Decode(&p); err != nil {
		return p, err
	}
	_, a, e1 := net.ParseCIDR(p.VPNCIDR)
	_, b, e2 := net.ParseCIDR(p.LANCIDR)
	if e1 != nil || e2 != nil || a.IP.To4() == nil || b.IP.To4() == nil || a.Contains(b.IP) || b.Contains(a.IP) {
		return p, errors.New("invalid runtime NAT network plan")
	}
	return p, nil
}

type rule struct {
	Table string
	Args  []string
}

func natRules(p NetworkPlan) []rule {
	return []rule{
		{"filter", []string{"FORWARD", "-i", "tun0", "-o", "eth0", "-s", p.VPNCIDR, "-d", p.LANCIDR, "-j", "ACCEPT"}},
		{"filter", []string{"FORWARD", "-i", "eth0", "-o", "tun0", "-s", p.LANCIDR, "-d", p.VPNCIDR, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		{"nat", []string{"POSTROUTING", "-s", p.VPNCIDR, "-d", p.LANCIDR, "-o", "eth0", "-j", "MASQUERADE"}},
	}
}
func iptables(rule rule, op string) error {
	args := []string{"-w", "-t", rule.Table, op}
	args = append(args, rule.Args...)
	cmd := exec.Command("/usr/sbin/iptables", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables %s %s failed: %w", rule.Table, op, err)
	}
	return nil
}
func (c *Controller) applyNetwork() error {
	plan, err := loadNetwork(filepath.Join(filepath.Dir(c.ConfigPath), "network.json"))
	if err != nil {
		return err
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil || strings.TrimSpace(string(b)) != "1" {
		return errors.New("container IPv4 forwarding is disabled")
	}
	for _, rule := range natRules(plan) {
		if iptables(rule, "-C") == nil {
			continue
		}
		if err := iptables(rule, "-A"); err != nil {
			return err
		}
		c.activeRules = append(c.activeRules, rule)
	}
	return nil
}
func (c *Controller) clearNetwork() {
	for i := len(c.activeRules) - 1; i >= 0; i-- {
		_ = iptables(c.activeRules[i], "-D")
	}
	c.activeRules = nil
}
