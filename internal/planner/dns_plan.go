package planner

import "github.com/whitedns/wdns-wizard/pkg/types"

// GenerateIranDNSPlan returns the DNS records the tool manages for the Iran
// domestic-fronting profile. The .ir CDN fronts live on ArvanCloud (outside this
// tool, and Cloudflare is BLOCKED in Iran), so NO .ir CDN A-records are emitted.
// Optionally a single non-proxied origin A-record is returned when an origin
// subdomain is provided; otherwise the plan is empty. This keeps the Iran path
// fully Cloudflare-decoupled.
func GenerateIranDNSPlan(originHost, vpsIP string) types.DNSPlan {
	if originHost == "" || vpsIP == "" {
		return types.DNSPlan{}
	}
	return types.DNSPlan{Records: []types.DNSRecord{
		{
			Name:    originHost,
			Type:    "A",
			Content: vpsIP,
			Proxied: false, // origin only; never proxied, never a .ir CDN front
			TTL:     types.DefaultTTL,
			Purpose: "iran_origin",
		},
	}}
}

func GenerateDNSPlan(domain, vpsIP string) types.DNSPlan {
	return types.DNSPlan{Records: []types.DNSRecord{
		{
			Name:    "vpn." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: true,
			TTL:     types.DefaultTTL,
			Purpose: "vless_ws_tls",
		},
		{
			Name:    "trojan." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: true,
			TTL:     types.DefaultTTL,
			Purpose: "vless_ws_tls_8443",
		},
		{
			Name:    "panel." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "xui_panel_placeholder",
		},
		{
			Name:    "direct." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "direct_fallback",
		},
		{
			Name:    "hy2." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "hysteria2_direct_placeholder",
		},
		{
			Name:    "reality." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "reality_xhttp_direct",
		},
		{
			Name:    "ss." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "shadowsocks_direct",
		},
		{
			Name:    "tor-vless-ws." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "tor_vless_ws_tls",
		},
		{
			Name:    "tor-vless-ws-8443." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "tor_vless_ws_tls_8443",
		},
		{
			Name:    "tor-hy2." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "tor_hysteria2_direct",
		},
		{
			Name:    "tor-direct." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "tor_direct_vless_tcp_tls",
		},
		{
			Name:    "tor-reality." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "tor_reality_xhttp_direct",
		},
		{
			Name:    "tor-ss." + domain,
			Type:    "A",
			Content: vpsIP,
			Proxied: false,
			TTL:     types.DefaultTTL,
			Purpose: "tor_shadowsocks_direct",
		},
	}}
}
