package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	PublicHost string `json:"publicHost"`
	VPNCIDR    string `json:"vpnCIDR"`
	LANCIDR    string `json:"lanCIDR"`
	DNS        string `json:"dns"`
}

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func ValidConfig(c Config) error {
	if len(c.PublicHost) > 253 || !hostnamePattern.MatchString(c.PublicHost) || strings.Contains(c.PublicHost, "..") {
		return errors.New("invalid public host")
	}
	if ip := net.ParseIP(c.PublicHost); ip != nil && ip.To4() == nil {
		return errors.New("IPv6 public host unsupported")
	}
	_, vpn, err := net.ParseCIDR(c.VPNCIDR)
	if err != nil || vpn.IP.To4() == nil {
		return errors.New("invalid IPv4 VPN CIDR")
	}
	ones, bits := vpn.Mask.Size()
	if bits != 32 || ones < 16 || ones > 29 {
		return errors.New("VPN prefix must be /16 through /29")
	}
	_, lan, err := net.ParseCIDR(c.LANCIDR)
	if err != nil || lan.IP.To4() == nil {
		return errors.New("invalid IPv4 LAN CIDR")
	}
	if vpn.Contains(lan.IP) || lan.Contains(vpn.IP) {
		return errors.New("overlapping VPN and LAN networks")
	}
	dns := net.ParseIP(c.DNS)
	if dns == nil || dns.To4() == nil {
		return errors.New("DNS must be IPv4 address")
	}
	return nil
}
func Render(c Config) (string, error) {
	if err := ValidConfig(c); err != nil {
		return "", err
	}
	_, vpn, _ := net.ParseCIDR(c.VPNCIDR)
	_, lan, _ := net.ParseCIDR(c.LANCIDR)
	vpnAddr := vpn.IP.Mask(vpn.Mask).String()
	mask := net.IP(vpn.Mask).String()
	lanMask := net.IP(lan.Mask).String()
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Managed by OpenVPN CE Manager. Do not edit directly.\n")
	fmt.Fprintf(&b, "port 1194\nproto tcp-server\ndev tun\ntopology subnet\nserver %s %s\n", vpnAddr, mask)
	fmt.Fprintf(&b, "push \"route %s %s\"\npush \"dhcp-option DNS %s\"\n", lan.IP.Mask(lan.Mask), lanMask, c.DNS)
	b.WriteString("ca /etc/openvpn/ca.crt\ncert /etc/openvpn/server.crt\nkey /etc/openvpn/server.key\ncrl-verify /etc/openvpn/crl.pem\n")
	b.WriteString("tls-crypt /etc/openvpn/tls-crypt.key\ndh none\n")
	b.WriteString("data-ciphers AES-256-GCM:AES-128-GCM\n")
	b.WriteString("verify-client-cert require\ntls-version-min 1.2\n")
	b.WriteString("persist-key\npersist-tun\nkeepalive 10 120\n")
	b.WriteString("status /run/openvpn/status.log 10\nstatus-version 3\nverb 3\n")
	b.WriteString("management /run/openvpn/management.sock unix /run/openvpn/management.pass\n")
	return b.String(), nil
}
func ReadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	if err == nil {
		err = ValidConfig(c)
	}
	return c, err
}
func AtomicFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".new-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if dirFd, err := os.Open(dir); err == nil {
		_ = dirFd.Sync()
		_ = dirFd.Close()
	}
	return nil
}
