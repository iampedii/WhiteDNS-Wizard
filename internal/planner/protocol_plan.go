package planner

import (
	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

func GenerateProtocolPlan(domain string, generated secrets.GeneratedSecrets) types.ProtocolPlan {
	clientSuffix := clientSuffix(domain)
	return types.ProtocolPlan{Protocols: []types.Protocol{
		{
			Name:              "vless_ws_tls",
			Enabled:           true,
			Hostname:          "vpn." + domain,
			Port:              443,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-vless-ws",
			ClientEmail:       "WhiteDNS-vless-" + clientSuffix,
			Path:              generated.VLESSWSPath,
			TLS:               true,
			CloudflareProxied: true,
			Certificate:       "origin_ca",
		},
		{
			Name:              "vless_ws_tls_8443",
			Enabled:           true,
			Hostname:          "trojan." + domain,
			Port:              8443,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-vless-ws-8443",
			ClientEmail:       "WhiteDNS-vless-8443-" + clientSuffix,
			Path:              generated.TrojanWSPath,
			TLS:               true,
			CloudflareProxied: true,
			Certificate:       "origin_ca",
		},
		{
			Name:              "hysteria2_direct",
			Enabled:           true,
			Hostname:          "hy2." + domain,
			Port:              443,
			Network:           "udp",
			Transport:         "hysteria2",
			Tag:               "wdns-hysteria2",
			ClientEmail:       "WhiteDNS-hy2-" + clientSuffix,
			UDP:               true,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "direct_vless_tcp_tls",
			Enabled:           true,
			Hostname:          "direct." + domain,
			Port:              2087,
			Network:           "tcp",
			Transport:         "tcp",
			Tag:               "wdns-direct-vless",
			ClientEmail:       "WhiteDNS-direct-" + clientSuffix,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "reality_xhttp_direct",
			Enabled:           true,
			Hostname:          "reality." + domain,
			Port:              2083,
			Network:           "tcp",
			Transport:         "xhttp",
			Tag:               "wdns-reality-xhttp",
			ClientEmail:       "WhiteDNS-reality-" + clientSuffix,
			Path:              "/",
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "reality",
		},
		{
			Name:              "shadowsocks_direct",
			Enabled:           true,
			Hostname:          "ss." + domain,
			Port:              8388,
			Network:           "tcp,udp",
			Transport:         "shadowsocks",
			Tag:               "wdns-shadowsocks",
			ClientEmail:       "WhiteDNS-ss-" + clientSuffix,
			CloudflareProxied: false,
			Certificate:       "none",
		},
		{
			Name:              "tor_vless_ws_tls",
			Enabled:           true,
			Hostname:          "tor-vless-ws." + domain,
			Port:              2097,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-tor-vless-ws",
			ClientEmail:       "WhiteDNS-tor-vless-" + clientSuffix,
			Path:              generated.VLESSWSPath,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_vless_ws_tls_8443",
			Enabled:           true,
			Hostname:          "tor-vless-ws-8443." + domain,
			Port:              2098,
			Network:           "tcp",
			Transport:         "ws",
			Tag:               "wdns-tor-vless-ws-8443",
			ClientEmail:       "WhiteDNS-tor-vless-8443-" + clientSuffix,
			Path:              generated.TrojanWSPath,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_hysteria2_direct",
			Enabled:           true,
			Hostname:          "tor-hy2." + domain,
			Port:              2099,
			Network:           "udp",
			Transport:         "hysteria2",
			Tag:               "wdns-tor-hysteria2",
			ClientEmail:       "WhiteDNS-tor-hy2-" + clientSuffix,
			UDP:               true,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_direct_vless_tcp_tls",
			Enabled:           true,
			Hostname:          "tor-direct." + domain,
			Port:              2100,
			Network:           "tcp",
			Transport:         "tcp",
			Tag:               "wdns-tor-direct-vless",
			ClientEmail:       "WhiteDNS-tor-direct-" + clientSuffix,
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "public_acme",
		},
		{
			Name:              "tor_reality_xhttp_direct",
			Enabled:           true,
			Hostname:          "tor-reality." + domain,
			Port:              2101,
			Network:           "tcp",
			Transport:         "xhttp",
			Tag:               "wdns-tor-reality-xhttp",
			ClientEmail:       "WhiteDNS-tor-reality-" + clientSuffix,
			Path:              "/",
			TLS:               true,
			CloudflareProxied: false,
			Certificate:       "reality",
		},
		{
			Name:              "tor_shadowsocks_direct",
			Enabled:           true,
			Hostname:          "tor-ss." + domain,
			Port:              8390,
			Network:           "tcp,udp",
			Transport:         "shadowsocks",
			Tag:               "wdns-tor-shadowsocks",
			ClientEmail:       "WhiteDNS-tor-ss-" + clientSuffix,
			CloudflareProxied: false,
			Certificate:       "none",
		},
	}}
}

// IranFrontingInput carries the operator-supplied, rotatable fronting values for
// the Iran domestic-CDN profiles. Empty fields fall back to safe seeded defaults
// (the owner-controlled abshardejh.ir front). The Example.txt tenant domains are
// never hardcoded as truth here.
type IranFrontingInput struct {
	Front     string // .ir SNI/Host for the XHTTP-TLS profile (SNI == Host; ArvanCloud 403 on mismatch)
	CDNHost   string // connect address for the XHTTP-TLS profile (clean ArvanCloud edge host/IP)
	CDNPort   int    // edge port for the XHTTP-TLS profile (one of 2053/2083/2087/8443)
	WSFront   string // .ir HTTP Host header for the WS-none profile (differs from connect address)
	WSAddress string // high-collateral .ir connect decoy for the WS-none profile
	WSPort    int    // edge port for the WS-none profile (one of 8880/2086/8080/2095/2052)
	TCPHost   string // camouflage .ir host for the TCP+HTTP-header profile
	TCPPort   int    // L4 passthrough port (56201–56207)
}

func (in IranFrontingInput) withDefaults() IranFrontingInput {
	front := firstNonEmptyPlan(in.Front, secrets.DefaultIranFront())
	if in.CDNHost == "" {
		in.CDNHost = front
	}
	if in.CDNPort == 0 {
		in.CDNPort = 2053
	}
	in.Front = front
	if in.WSFront == "" {
		in.WSFront = front
	}
	if in.WSAddress == "" {
		in.WSAddress = "snapp.ir"
	}
	if in.WSPort == 0 {
		in.WSPort = 8880
	}
	if in.TCPHost == "" {
		in.TCPHost = front
	}
	if in.TCPPort == 0 {
		in.TCPPort = 56201
	}
	return in
}

// GenerateIranProtocolPlan returns the three Iran domestic-fronting profiles
// (XHTTP-over-TLS, WS-security=none with a .ir Host decoy, and TCP+HTTP-header
// camouflage). They are gated behind Profile == "iran-domestic" so the default
// Cloudflare flow and its test counts are unaffected when the profile is unused.
func GenerateIranProtocolPlan(domain string, front IranFrontingInput, generated secrets.GeneratedSecrets) types.ProtocolPlan {
	front = front.withDefaults()
	clientSuffix := clientSuffix(domain)
	wsPath := firstNonEmptyPlan(generated.IranWSPath, secrets.DefaultIranWSPath)
	return types.ProtocolPlan{Protocols: []types.Protocol{
		{
			Name:              "iran_xhttp_tls",
			Enabled:           true,
			Profile:           "iran-domestic",
			Hostname:          front.CDNHost,
			Address:           front.CDNHost, // clean ArvanCloud edge host/IP (operator input)
			Host:              front.Front,   // front .ir — MUST equal ServerName (Arvan 403 on mismatch)
			ServerName:        front.Front,
			Port:              front.CDNPort,
			Network:           "xhttp",
			Transport:         "xhttp",
			Security:          "tls",
			TLS:               true,
			Tag:               "wdns-iran-xhttp-cdn",
			ClientEmail:       "WhiteDNS-iran-xhttp-" + clientSuffix,
			Path:              "/",
			CloudflareProxied: false,
			Certificate:       "none",
			CertMode:          "origin-http",
			Extra:             `{"scMaxEachPostBytes":1000000,"scMinPostsIntervalMs":30,"xPaddingBytes":"100-1000","noGRPCHeader":false}`,
		},
		{
			Name:              "iran_ws_none",
			Enabled:           true,
			Profile:           "iran-domestic",
			Hostname:          front.WSAddress,
			Address:           front.WSAddress, // high-collateral .ir connect decoy (operator input)
			Host:              front.WSFront,   // .ir front — DIFFERS from Address
			ServerName:        "",              // no SNI (security=none)
			Port:              front.WSPort,
			Network:           "ws",
			Transport:         "ws",
			Security:          "none",
			TLS:               false,
			Tag:               "wdns-iran-ws-cdn",
			ClientEmail:       "WhiteDNS-iran-ws-" + clientSuffix,
			Path:              wsPath,
			CloudflareProxied: false,
			Certificate:       "none",
			CertMode:          "origin-http",
		},
		{
			Name:              "iran_tcp_http",
			Enabled:           true,
			Profile:           "iran-domestic",
			Hostname:          front.TCPHost,
			Address:           front.TCPHost, // camouflage .ir host (operator input)
			Host:              "",
			ServerName:        "",
			Port:              front.TCPPort,
			Network:           "tcp",
			Transport:         "tcp",
			Security:          "none",
			TLS:               false,
			HeaderType:        "http",
			Tag:               "wdns-iran-tcp-http",
			ClientEmail:       "WhiteDNS-iran-tcp-" + clientSuffix,
			Path:              "/",
			CloudflareProxied: false,
			Certificate:       "none",
			CertMode:          "origin-http",
		},
	}}
}

func firstNonEmptyPlan(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func clientSuffix(domain string) string {
	out := make([]byte, 0, len(domain))
	for i := 0; i < len(domain); i++ {
		ch := domain[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			out = append(out, ch)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}
