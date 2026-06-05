package xui

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/whitedns/wdns-wizard/internal/planner"
	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

const (
	RemoteBaseDir           = "/opt/wdns-wizard/3x-ui"
	RemoteComposePath       = RemoteBaseDir + "/docker-compose.yml"
	RemoteTorDockerfilePath = RemoteBaseDir + "/tor/Dockerfile"
	RemoteTorrcPath         = RemoteBaseDir + "/tor/torrc"
	RemoteOriginCertPath    = "/root/cert/wdns/origin.pem"
	RemoteOriginKeyPath     = "/root/cert/wdns/origin.key"
	RemotePublicCertPath    = "/root/cert/wdns/public.pem"
	RemotePublicKeyPath     = "/root/cert/wdns/public.key"

	HostOriginCertPath = RemoteBaseDir + "/cert/wdns/origin.pem"
	HostOriginKeyPath  = RemoteBaseDir + "/cert/wdns/origin.key"
	HostPublicCertPath = RemoteBaseDir + "/cert/wdns/public.pem"
	HostPublicKeyPath  = RemoteBaseDir + "/cert/wdns/public.key"

	PanelPort = 2053

	noTrustedXFFSentinel = "WhiteDNS-No-Trusted-XFF"
)

type ProtocolBundle struct {
	Plan     types.ProtocolPlan
	Links    types.ClientLinks
	Inbounds []Inbound
}

func BuildProtocolBundle(domain string, values map[string]string) (ProtocolBundle, error) {
	generated := secrets.GeneratedSecrets{
		VLESSUUID:              values["vless_uuid"],
		VLESS8443UUID:          values["vless_8443_uuid"],
		DirectVLESSUUID:        values["direct_vless_uuid"],
		RealityVLESSUUID:       values["reality_vless_uuid"],
		RealityPrivateKey:      values["reality_private_key"],
		RealityPublicKey:       values["reality_public_key"],
		RealityShortID:         values["reality_short_id"],
		RealityMLDSA65Seed:     values["reality_mldsa65_seed"],
		RealityMLKEMDecryption: values["reality_mlkem_decryption"],
		RealityMLKEMEncryption: values["reality_mlkem_encryption"],
		RealitySNI:             values["reality_sni"],
		TrojanPassword:         values["trojan_password"],
		Hysteria2Password:      values["hysteria2_password"],
		Hysteria2ObfsPassword:  values["hysteria2_obfs_password"],
		ShadowsocksServerPass:  values["shadowsocks_server_password"],
		ShadowsocksClientPass:  values["shadowsocks_client_password"],
		TorVLESSUUID:           values["tor_vless_uuid"],
		TorVLESS8443UUID:       values["tor_vless_8443_uuid"],
		TorDirectVLESSUUID:     values["tor_direct_vless_uuid"],
		TorRealityVLESSUUID:    values["tor_reality_vless_uuid"],
		TorRealityPrivateKey:   values["tor_reality_private_key"],
		TorRealityPublicKey:    values["tor_reality_public_key"],
		TorRealityShortID:      values["tor_reality_short_id"],
		TorRealityMLDSA65Seed:  values["tor_reality_mldsa65_seed"],
		TorRealityMLKEMDecrypt: values["tor_reality_mlkem_decryption"],
		TorRealityMLKEMEncrypt: values["tor_reality_mlkem_encryption"],
		TorRealitySNI:          values["tor_reality_sni"],
		TorHysteria2Password:   values["tor_hysteria2_password"],
		TorHysteria2ObfsPass:   values["tor_hysteria2_obfs_password"],
		TorShadowsocksServer:   values["tor_shadowsocks_server_password"],
		TorShadowsocksClient:   values["tor_shadowsocks_client_password"],
		VLESSWSPath:            values["vless_ws_path"],
		TrojanWSPath:           values["trojan_ws_path"],
		IranXHTTPUUID:          values["iran_xhttp_uuid"],
		IranWSUUID:             values["iran_ws_uuid"],
		IranTCPUUID:            values["iran_tcp_uuid"],
		IranWSPath:             values["iran_ws_path"],
	}
	plan := planner.GenerateProtocolPlan(domain, generated)
	var links []types.ClientLink
	var inbounds []Inbound
	for _, proto := range plan.Protocols {
		if !proto.Enabled {
			continue
		}
		inbound, link, err := inboundAndLink(proto, values)
		if err != nil {
			return ProtocolBundle{}, err
		}
		inbounds = append(inbounds, inbound)
		links = append(links, link)
	}
	return ProtocolBundle{
		Plan:     plan,
		Links:    types.ClientLinks{Clients: links},
		Inbounds: inbounds,
	}, nil
}

// BuildIranProtocolBundle builds the three Iran domestic-fronting profiles
// (XHTTP-over-TLS, WS-security=none, TCP+HTTP-header). It rides the same
// inbound/link machinery as BuildProtocolBundle but emits only the Iran
// profiles, with no Cloudflare/ACME dependency. Fronts are operator-supplied and
// rotatable (front), validated against the ArvanCloud SNI==Host / Address!=Host
// invariants before any inbound is built.
func BuildIranProtocolBundle(domain string, front planner.IranFrontingInput, values map[string]string) (ProtocolBundle, error) {
	generated := secrets.GeneratedSecrets{IranWSPath: values["iran_ws_path"]}
	plan := planner.GenerateIranProtocolPlan(domain, front, generated)
	if err := planner.ValidateIranPlan(plan); err != nil {
		return ProtocolBundle{}, err
	}
	var links []types.ClientLink
	var inbounds []Inbound
	for _, proto := range plan.Protocols {
		if !proto.Enabled {
			continue
		}
		inbound, link, err := inboundAndLink(proto, values)
		if err != nil {
			return ProtocolBundle{}, err
		}
		inbounds = append(inbounds, inbound)
		links = append(links, link)
	}
	return ProtocolBundle{
		Plan:     plan,
		Links:    types.ClientLinks{Clients: links},
		Inbounds: inbounds,
	}, nil
}

func inboundAndLink(proto types.Protocol, values map[string]string) (Inbound, types.ClientLink, error) {
	switch proto.Name {
	case "vless_ws_tls":
		uuid := required(values, "vless_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = wsTLSStream(proto, RemoteOriginCertPath, RemoteOriginKeyPath)
		return inbound, link(proto, vlessWSLink(proto, uuid)), nil
	case "vless_ws_tls_8443":
		uuid := required(values, "vless_8443_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = wsTLSStream(proto, RemoteOriginCertPath, RemoteOriginKeyPath)
		return inbound, link(proto, vlessWSLink(proto, uuid)), nil
	case "hysteria2_direct":
		auth := required(values, "hysteria2_password")
		obfsPassword := required(values, "hysteria2_obfs_password")
		inbound := baseInbound(proto, "hysteria")
		inbound.Settings = map[string]any{
			"clients": []map[string]any{hysteriaClient(auth, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"version": 2,
		}
		inbound.StreamSettings = map[string]any{
			"network":       "hysteria",
			"security":      "tls",
			"externalProxy": []any{},
			"hysteriaSettings": map[string]any{
				"version":        2,
				"auth":           auth,
				"udpIdleTimeout": 60,
			},
			"finalmask": map[string]any{
				"udp": []map[string]any{
					{
						"type": "salamander",
						"settings": map[string]any{
							"password": obfsPassword,
						},
					},
				},
				"quicParams": map[string]any{
					"congestion": "bbr",
				},
			},
			"tlsSettings": tlsSettingsWithALPN(proto.Hostname, RemotePublicCertPath, RemotePublicKeyPath, []string{"h3"}),
		}
		inbound.Sniffing = map[string]any{"enabled": false}
		return inbound, link(proto, hysteria2Link(proto, auth, obfsPassword)), nil
	case "direct_vless_tcp_tls":
		uuid := required(values, "direct_vless_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = map[string]any{
			"network":     "tcp",
			"security":    "tls",
			"tcpSettings": map[string]any{"acceptProxyProtocol": false, "header": map[string]any{"type": "none"}},
			"tlsSettings": tlsSettings(proto.Hostname, RemotePublicCertPath, RemotePublicKeyPath),
			"sockopt":     map[string]any{},
		}
		return inbound, link(proto, directVLESSLink(proto, uuid)), nil
	case "reality_xhttp_direct":
		uuid := required(values, "reality_vless_uuid")
		publicKey := required(values, "reality_public_key")
		shortID := required(values, "reality_short_id")
		sni := realitySNI(values, "reality")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = realityXHTTPStream(values, "reality")
		inbound.Sniffing = map[string]any{"enabled": false}
		return inbound, link(proto, realityVLESSLink(proto, uuid, publicKey, shortID, sni)), nil
	case "shadowsocks_direct":
		serverPassword := required(values, "shadowsocks_server_password")
		clientPassword := required(values, "shadowsocks_client_password")
		inbound := baseInbound(proto, "shadowsocks")
		inbound.Settings = map[string]any{
			"method":   shadowsocksMethod(),
			"password": serverPassword,
			"network":  "tcp,udp",
			"clients":  []map[string]any{shadowsocksClient(clientPassword, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
		}
		inbound.StreamSettings = map[string]any{
			"network":  "tcp",
			"security": "none",
			"tcpSettings": map[string]any{
				"acceptProxyProtocol": false,
				"header":              map[string]any{"type": "none"},
			},
		}
		return inbound, link(proto, shadowsocksLink(proto, serverPassword, clientPassword)), nil
	case "tor_vless_ws_tls":
		uuid := required(values, "tor_vless_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = wsTLSStream(proto, RemotePublicCertPath, RemotePublicKeyPath)
		return inbound, link(proto, vlessWSLink(proto, uuid)), nil
	case "tor_vless_ws_tls_8443":
		uuid := required(values, "tor_vless_8443_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = wsTLSStream(proto, RemotePublicCertPath, RemotePublicKeyPath)
		return inbound, link(proto, vlessWSLink(proto, uuid)), nil
	case "tor_hysteria2_direct":
		auth := required(values, "tor_hysteria2_password")
		obfsPassword := required(values, "tor_hysteria2_obfs_password")
		inbound := baseInbound(proto, "hysteria")
		inbound.Settings = map[string]any{
			"clients": []map[string]any{hysteriaClient(auth, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"version": 2,
		}
		inbound.StreamSettings = map[string]any{
			"network":       "hysteria",
			"security":      "tls",
			"externalProxy": []any{},
			"hysteriaSettings": map[string]any{
				"version":        2,
				"auth":           auth,
				"udpIdleTimeout": 60,
			},
			"finalmask": map[string]any{
				"udp": []map[string]any{
					{
						"type": "salamander",
						"settings": map[string]any{
							"password": obfsPassword,
						},
					},
				},
				"quicParams": map[string]any{
					"congestion": "bbr",
				},
			},
			"tlsSettings": tlsSettingsWithALPN(proto.Hostname, RemotePublicCertPath, RemotePublicKeyPath, []string{"h3"}),
		}
		inbound.Sniffing = map[string]any{"enabled": false}
		return inbound, link(proto, hysteria2Link(proto, auth, obfsPassword)), nil
	case "tor_direct_vless_tcp_tls":
		uuid := required(values, "tor_direct_vless_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = map[string]any{
			"network":     "tcp",
			"security":    "tls",
			"tcpSettings": map[string]any{"acceptProxyProtocol": false, "header": map[string]any{"type": "none"}},
			"tlsSettings": tlsSettings(proto.Hostname, RemotePublicCertPath, RemotePublicKeyPath),
			"sockopt":     map[string]any{},
		}
		return inbound, link(proto, directVLESSLink(proto, uuid)), nil
	case "tor_reality_xhttp_direct":
		uuid := required(values, "tor_reality_vless_uuid")
		publicKey := required(values, "tor_reality_public_key")
		shortID := required(values, "tor_reality_short_id")
		sni := realitySNI(values, "tor_reality")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = realityXHTTPStream(values, "tor_reality")
		inbound.Sniffing = map[string]any{"enabled": false}
		return inbound, link(proto, realityVLESSLink(proto, uuid, publicKey, shortID, sni)), nil
	case "tor_shadowsocks_direct":
		serverPassword := required(values, "tor_shadowsocks_server_password")
		clientPassword := required(values, "tor_shadowsocks_client_password")
		inbound := baseInbound(proto, "shadowsocks")
		inbound.Settings = map[string]any{
			"method":   shadowsocksMethod(),
			"password": serverPassword,
			"network":  "tcp,udp",
			"clients":  []map[string]any{shadowsocksClient(clientPassword, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
		}
		inbound.StreamSettings = map[string]any{
			"network":  "tcp",
			"security": "none",
			"tcpSettings": map[string]any{
				"acceptProxyProtocol": false,
				"header":              map[string]any{"type": "none"},
			},
		}
		return inbound, link(proto, shadowsocksLink(proto, serverPassword, clientPassword)), nil
	case "iran_xhttp_tls":
		uuid := required(values, "iran_xhttp_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = iranXHTTPTLSStream(proto)
		inbound.Sniffing = map[string]any{"enabled": false}
		return inbound, link(proto, iranXHTTPLink(proto, uuid)), nil
	case "iran_ws_none":
		uuid := required(values, "iran_ws_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = iranWSNoneStream(proto)
		inbound.Sniffing = map[string]any{"enabled": false}
		return inbound, link(proto, iranWSLink(proto, uuid)), nil
	case "iran_tcp_http":
		uuid := required(values, "iran_tcp_uuid")
		inbound := baseInbound(proto, "vless")
		inbound.Settings = map[string]any{
			"clients":    []map[string]any{vlessClient(uuid, proto.ClientEmail, DisplayNameForTag(proto.Tag))},
			"decryption": "none",
			"fallbacks":  []any{},
		}
		inbound.StreamSettings = iranTCPHTTPStream(proto)
		inbound.Sniffing = map[string]any{"enabled": false}
		return inbound, link(proto, iranTCPHTTPLink(proto, uuid)), nil
	default:
		return Inbound{}, types.ClientLink{}, fmt.Errorf("unsupported protocol %q", proto.Name)
	}
}

func shadowsocksMethod() string {
	return "2022-blake3-aes-256-gcm"
}

// RenderIranChecklist returns the manual ArvanCloud setup checklist for the Iran
// domestic-fronting profiles. The tool assumes the CDN exists and never calls
// the ArvanCloud panel/API (owner policy + NS delegation is registrar-only).
func RenderIranChecklist() string {
	return strings.Join([]string{
		"Manual ArvanCloud checklist (the tool does NOT provision the CDN):",
		"1. Add each .ir front domain to an ArvanCloud CDN account you control (seed: abshardejh.ir).",
		"2. Point the CDN origin to this VPS; set origin-pull to HTTP (CertMode origin-http) - no Origin-CA, no ACME.",
		"3. For the XHTTP-TLS front, ensure the client SNI == HTTP Host (ArvanCloud returns 403 on mismatch).",
		"4. For the WS-none decoy, keep the connect address different from the Host front and send no SNI.",
		"5. Open the origin/L4 ports (8080/tcp and 56201-56207/tcp) on the VPS firewall.",
		"6. Rotate fronts as needed - Example.txt tenant domains belong to other tenants and will die.",
	}, "\n")
}

func required(values map[string]string, key string) string {
	return strings.TrimSpace(values[key])
}

func baseInbound(proto types.Protocol, protocol string) Inbound {
	return Inbound{
		Remark:         DisplayNameForTag(proto.Tag),
		Enable:         true,
		Port:           proto.Port,
		Protocol:       protocol,
		Tag:            proto.Tag,
		Settings:       map[string]any{},
		StreamSettings: map[string]any{},
		Sniffing: map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic", "fakedns"},
		},
	}
}

func vlessClient(uuid, email, comment string) map[string]any {
	return map[string]any{
		"id":         uuid,
		"flow":       "",
		"email":      email,
		"limitIp":    0,
		"totalGB":    0,
		"expiryTime": 0,
		"enable":     true,
		"tgId":       0,
		"subId":      shortSubID(uuid),
		"comment":    comment,
		"reset":      0,
	}
}

func hysteriaClient(auth, email, comment string) map[string]any {
	return map[string]any{
		"id":         "",
		"auth":       auth,
		"flow":       "",
		"security":   "auto",
		"email":      email,
		"limitIp":    0,
		"totalGB":    0,
		"expiryTime": 0,
		"enable":     true,
		"tgId":       0,
		"subId":      shortSubID(auth),
		"comment":    comment,
		"reset":      0,
		"password":   "",
	}
}

func shadowsocksClient(password, email, comment string) map[string]any {
	return map[string]any{
		"id":         "",
		"auth":       "",
		"flow":       "",
		"security":   "auto",
		"email":      email,
		"limitIp":    0,
		"totalGB":    0,
		"expiryTime": 0,
		"enable":     true,
		"tgId":       0,
		"subId":      shortSubID(password),
		"comment":    comment,
		"reset":      0,
		"password":   password,
	}
}

func shortSubID(value string) string {
	value = strings.NewReplacer("-", "", "_", "").Replace(value)
	if len(value) > 16 {
		return value[:16]
	}
	return value
}

func wsTLSStream(proto types.Protocol, certPath, keyPath string) map[string]any {
	return map[string]any{
		"network":  "ws",
		"security": "tls",
		"wsSettings": map[string]any{
			"path": proto.Path,
			"host": proto.Hostname,
		},
		"tlsSettings": tlsSettings(proto.Hostname, certPath, keyPath),
		"sockopt": map[string]any{
			"trustedXForwardedFor": []string{noTrustedXFFSentinel},
		},
	}
}

func tlsSettings(serverName, certPath, keyPath string) map[string]any {
	return tlsSettingsWithALPN(serverName, certPath, keyPath, []string{"h2", "http/1.1"})
}

func tlsSettingsWithALPN(serverName, certPath, keyPath string, alpn []string) map[string]any {
	return map[string]any{
		"serverName": serverName,
		"minVersion": "1.2",
		"alpn":       alpn,
		"certificates": []map[string]any{
			{
				"certificateFile": certPath,
				"keyFile":         keyPath,
			},
		},
	}
}

func realityXHTTPStream(values map[string]string, prefix string) map[string]any {
	sni := realitySNI(values, prefix)
	return map[string]any{
		"network": "xhttp",
		"xhttpSettings": map[string]any{
			"path":                 "/",
			"host":                 "",
			"mode":                 "auto",
			"xPaddingBytes":        "100-1000",
			"xPaddingObfsMode":     false,
			"xPaddingKey":          "",
			"xPaddingHeader":       "",
			"xPaddingPlacement":    "",
			"xPaddingMethod":       "",
			"sessionPlacement":     "",
			"sessionKey":           "",
			"seqPlacement":         "",
			"seqKey":               "",
			"uplinkDataPlacement":  "",
			"uplinkDataKey":        "",
			"scMaxEachPostBytes":   "1000000",
			"noSSEHeader":          false,
			"scMaxBufferedPosts":   30,
			"scStreamUpServerSecs": "20-80",
			"serverMaxHeaderBytes": 0,
			"uplinkHTTPMethod":     "",
			"headers":              map[string]any{},
			"scMinPostsIntervalMs": "30",
			"uplinkChunkSize":      0,
			"noGRPCHeader":         false,
			"enableXmux":           false,
		},
		"security": "reality",
		"sockopt": map[string]any{
			"trustedXForwardedFor": []string{noTrustedXFFSentinel},
		},
		"realitySettings": map[string]any{
			"show":         false,
			"xver":         0,
			"target":       sni + ":443",
			"serverNames":  []string{sni},
			"privateKey":   required(values, prefix+"_private_key"),
			"minClientVer": "",
			"maxClientVer": "",
			"maxTimediff":  0,
			"shortIds":     []string{required(values, prefix+"_short_id")},
			"mldsa65Seed":  required(values, prefix+"_mldsa65_seed"),
			"settings": map[string]any{
				"publicKey":   required(values, prefix+"_public_key"),
				"fingerprint": "chrome",
				"serverName":  "",
				"spiderX":     "/",
			},
		},
	}
}

// iranXHTTPTLSStream builds the origin inbound for the Iran XHTTP-over-TLS
// profile. ArvanCloud terminates client TLS at the edge, so the ORIGIN is
// security:none (the CDN origin-pulls over HTTP) - NOT reality and NOT tls. The
// dead scMaxConcurrentPosts field is never emitted; scMaxBufferedPosts:30 stays.
func iranXHTTPTLSStream(proto types.Protocol) map[string]any {
	return map[string]any{
		"network":  "xhttp",
		"security": "none", // origin behind CDN; NOT reality, NOT tls
		"xhttpSettings": map[string]any{
			"host":                 proto.ResolvedHost(), // front .ir; or "" to serve many fronts on one origin
			"path":                 "/",
			"mode":                 "auto",
			"scMaxEachPostBytes":   1000000,
			"scMaxBufferedPosts":   30,
			"scMinPostsIntervalMs": 30,
			"xPaddingBytes":        "100-1000",
			"noGRPCHeader":         false,
			"headers":              map[string]any{},
		},
		"sockopt": map[string]any{"trustedXForwardedFor": []string{noTrustedXFFSentinel}},
	}
}

// iranWSNoneStream builds the origin inbound for the Iran WS-security=none
// profile. The CDN terminates TLS on the HTTP-tier port; the origin is
// security:none. The server path strips the client-only ?ed= early-data marker.
func iranWSNoneStream(proto types.Protocol) map[string]any {
	return map[string]any{
		"network":  "ws",
		"security": "none",
		"wsSettings": map[string]any{
			"path": stripEarlyData(proto.Path), // client-only ?ed=; server prefix-matches
			"host": proto.ResolvedHost(),
		},
		"sockopt": map[string]any{"trustedXForwardedFor": []string{noTrustedXFFSentinel}},
	}
}

// iranTCPHTTPStream builds the origin inbound for the Iran TCP+fake-HTTP-header
// profile, carried over an ArvanCloud Layer-4 passthrough port. The origin
// terminates plain VLESS+TCP with HTTP-header camouflage.
func iranTCPHTTPStream(proto types.Protocol) map[string]any {
	return map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"acceptProxyProtocol": false,
			"header": map[string]any{
				"type": "http",
				"request": map[string]any{
					"version": "1.1",
					"method":  "GET",
					"path":    []string{"/"},
					"headers": map[string]any{
						"Host":            []string{"www.bing.com"},
						"User-Agent":      []string{"Mozilla/5.0"},
						"Accept-Encoding": []string{"gzip, deflate"},
						"Connection":      []string{"keep-alive"},
					},
				},
				"response": map[string]any{"version": "1.1", "status": "200", "reason": "OK"},
			},
		},
	}
}

// stripEarlyData removes the client-only ?ed= early-data query from a WS path so
// the server prefix-matches the bare path.
func stripEarlyData(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

func realitySNI(values map[string]string, prefix string) string {
	sni := strings.TrimSpace(values[prefix+"_sni"])
	if sni == "" {
		return secrets.DefaultRealitySNI()
	}
	return sni
}

func link(proto types.Protocol, raw string) types.ClientLink {
	return types.ClientLink{
		Name:     clientRemarkForTag(proto.Tag),
		Protocol: proto.Name,
		Hostname: proto.Hostname,
		Link:     raw,
	}
}

func vlessWSLink(proto types.Protocol, uuid string) string {
	q := orderedQuery(
		queryParam{"type", "ws"},
		queryParam{"security", "tls"},
		queryParam{"encryption", "none"},
		queryParam{"path", proto.Path},
		queryParam{"host", proto.Hostname},
		queryParam{"sni", proto.Hostname},
		queryParam{"fp", "chrome"},
	)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuid, proto.Hostname, proto.Port, q, fragmentEscape(clientRemarkForTag(proto.Tag)))
}

func hysteria2Link(proto types.Protocol, auth, obfsPassword string) string {
	q := orderedQuery(
		queryParam{"sni", proto.Hostname},
		queryParam{"alpn", "h3"},
		queryParam{"obfs", "salamander"},
		queryParam{"obfs-password", obfsPassword},
	)
	return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s", url.PathEscape(auth), proto.Hostname, proto.Port, q, fragmentEscape(clientRemarkForTag(proto.Tag)))
}

func directVLESSLink(proto types.Protocol, uuid string) string {
	q := orderedQuery(
		queryParam{"type", "tcp"},
		queryParam{"security", "tls"},
		queryParam{"encryption", "none"},
		queryParam{"sni", proto.Hostname},
		queryParam{"fp", "chrome"},
	)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuid, proto.Hostname, proto.Port, q, fragmentEscape(clientRemarkForTag(proto.Tag)))
}

func realityVLESSLink(proto types.Protocol, uuid, publicKey, shortID, sni string) string {
	q := orderedQuery(
		queryParam{"type", "xhttp"},
		queryParam{"security", "reality"},
		queryParam{"encryption", "none"},
		queryParam{"sni", sni},
		queryParam{"fp", "chrome"},
		queryParam{"pbk", publicKey},
		queryParam{"sid", shortID},
		queryParam{"path", "/"},
	)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuid, proto.Hostname, proto.Port, q, fragmentEscape(clientRemarkForTag(proto.Tag)))
}

// iranXHTTPLink builds the client link for the Iran XHTTP-over-TLS profile.
// security=tls describes the client->ArvanCloud-edge leg (the edge terminates
// it); SNI MUST equal Host (Arvan 403 on mismatch); fp is always chrome. The
// extra= JSON is minified (no spaces) and emitted through orderedQuery's
// extra-key special case, which forces any space to %20 (never the raw '+' that
// trips the v2rayN extra= parser) so the link stays spec-correct even if the
// JSON ever gains a space.
func iranXHTTPLink(proto types.Protocol, uuid string) string {
	q := orderedQuery(
		queryParam{"type", "xhttp"},
		queryParam{"security", "tls"},
		queryParam{"encryption", "none"},
		queryParam{"host", proto.ResolvedHost()},
		queryParam{"sni", proto.ResolvedServerName()},
		queryParam{"path", proto.Path},
		queryParam{"mode", "auto"},
		queryParam{"extra", proto.Extra},
		queryParam{"fp", "chrome"},
		queryParam{"alpn", "h2,http/1.1"},
	)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		uuid, proto.ResolvedAddress(), proto.Port, q, iranFragmentEscape(clientRemarkForTag(proto.Tag)))
}

// iranWSLink builds the client link for the Iran WS-security=none profile. No
// SNI is emitted; the connect address differs from the Host front; the path
// keeps the client-only ?ed= early-data marker.
func iranWSLink(proto types.Protocol, uuid string) string {
	q := orderedQuery(
		queryParam{"type", "ws"},
		queryParam{"security", "none"},
		queryParam{"encryption", "none"},
		queryParam{"path", proto.Path}, // keeps ?ed=2048
		queryParam{"host", proto.ResolvedHost()},
	)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		uuid, proto.ResolvedAddress(), proto.Port, q, iranFragmentEscape(clientRemarkForTag(proto.Tag)))
}

// iranTCPHTTPLink builds the client link for the Iran TCP+HTTP-header profile.
func iranTCPHTTPLink(proto types.Protocol, uuid string) string {
	q := orderedQuery(
		queryParam{"type", "tcp"},
		queryParam{"security", "none"},
		queryParam{"encryption", "none"},
		queryParam{"headerType", "http"},
		queryParam{"path", proto.Path},
		queryParam{"host", proto.ResolvedHost()},
	)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		uuid, proto.ResolvedAddress(), proto.Port, q, iranFragmentEscape(clientRemarkForTag(proto.Tag)))
}

func shadowsocksLink(proto types.Protocol, serverPassword, clientPassword string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(shadowsocksMethod() + ":" + serverPassword + ":" + clientPassword))
	q := orderedQuery(queryParam{"type", "tcp"})
	return fmt.Sprintf("ss://%s@%s:%d?%s#%s", encoded, proto.Hostname, proto.Port, q, fragmentEscape(clientRemarkForTag(proto.Tag)))
}

func clientRemarkForTag(tag string) string {
	switch strings.TrimSpace(tag) {
	case "wdns-vless-ws":
		return "VLESS WS @whiteDNS"
	case "wdns-vless-ws-8443":
		return "VLESS WS 8443 @whiteDNS"
	case "wdns-hysteria2":
		return "Hysteria2 @whiteDNS"
	case "wdns-direct-vless":
		return "Direct VLESS @whiteDNS"
	case "wdns-reality-xhttp":
		return "Reality XHTTP @whiteDNS"
	case "wdns-shadowsocks":
		return "Shadowsocks @whiteDNS"
	case "wdns-tor-vless-ws":
		return "VLESS WS Tor @whiteDNS"
	case "wdns-tor-vless-ws-8443":
		return "VLESS WS 8443 Tor @whiteDNS"
	case "wdns-tor-hysteria2":
		return "Hysteria2 Tor @whiteDNS"
	case "wdns-tor-direct-vless":
		return "Direct VLESS Tor @whiteDNS"
	case "wdns-tor-reality-xhttp":
		return "Reality XHTTP Tor @whiteDNS"
	case "wdns-tor-shadowsocks":
		return "Shadowsocks Tor @whiteDNS"
	case "wdns-iran-xhttp-cdn":
		return "Iran CDN XHTTP @whiteDNS"
	case "wdns-iran-ws-cdn":
		return "Iran CDN WS @whiteDNS"
	case "wdns-iran-tcp-http":
		return "Iran TCP HTTP @whiteDNS"
	default:
		return DisplayNameForTag(tag)
	}
}

func fragmentEscape(value string) string {
	return url.PathEscape(value)
}

// iranFragmentEscape single-encodes the link fragment for Iran profiles. It is
// the same single url.PathEscape as fragmentEscape but additionally encodes '@'
// as %40 so the "@whiteDNS" suffix renders identically to the Example.txt links
// - never the triple-encoding seen in the raw Example.txt fragments.
func iranFragmentEscape(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), "@", "%40")
}

func DisplayNameForTag(tag string) string {
	switch strings.TrimSpace(tag) {
	case "wdns-vless-ws":
		return "VLESS WS @whiteDNS"
	case "wdns-vless-ws-8443":
		return "VLESS WS 8443 @whiteDNS"
	case "wdns-hysteria2":
		return "Hysteria2 @whiteDNS"
	case "wdns-direct-vless":
		return "Direct VLESS @whiteDNS"
	case "wdns-reality-xhttp":
		return "Reality XHTTP @whiteDNS"
	case "wdns-shadowsocks":
		return "Shadowsocks @whiteDNS"
	case "wdns-tor-vless-ws":
		return "VLESS WS Tor @whiteDNS"
	case "wdns-tor-vless-ws-8443":
		return "VLESS WS 8443 Tor @whiteDNS"
	case "wdns-tor-hysteria2":
		return "Hysteria2 Tor @whiteDNS"
	case "wdns-tor-direct-vless":
		return "Direct VLESS Tor @whiteDNS"
	case "wdns-tor-reality-xhttp":
		return "Reality XHTTP Tor @whiteDNS"
	case "wdns-tor-shadowsocks":
		return "Shadowsocks Tor @whiteDNS"
	case "wdns-iran-xhttp-cdn":
		return "Iran CDN XHTTP @whiteDNS"
	case "wdns-iran-ws-cdn":
		return "Iran CDN WS @whiteDNS"
	case "wdns-iran-tcp-http":
		return "Iran TCP HTTP @whiteDNS"
	case "wdns-direct":
		return "Direct outbound @whiteDNS"
	case "wdns-blocked":
		return "Blocked outbound @whiteDNS"
	case "wdns-tor":
		return "Tor outbound @whiteDNS"
	default:
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tag)), "wdns-") {
			return strings.TrimPrefix(strings.TrimSpace(tag), "wdns-") + " @whiteDNS"
		}
		return tag
	}
}

type queryParam struct {
	key   string
	value string
}

func orderedQuery(params ...queryParam) string {
	parts := make([]string, 0, len(params))
	for _, param := range params {
		if strings.TrimSpace(param.value) == "" {
			continue
		}
		parts = append(parts, url.QueryEscape(param.key)+"="+escapeQueryValue(param.key, param.value))
	}
	return strings.Join(parts, "&")
}

// escapeQueryValue percent-encodes a query value. For every key except "extra"
// it is plain url.QueryEscape. For the XHTTP "extra" JSON it rewrites the '+'
// that url.QueryEscape emits for a space into %20 - url.QueryEscape maps a
// literal '+' to %2B, so a '+' in its output is unambiguously a space. The
// current extra JSON is minified (space-free), so this is a no-op today, but it
// guarantees the v2rayN extra= parser never sees a raw '+' if the JSON ever
// gains a space.
func escapeQueryValue(key, value string) string {
	escaped := url.QueryEscape(value)
	if key == "extra" {
		escaped = strings.ReplaceAll(escaped, "+", "%20")
	}
	return escaped
}

func outboundDirect() map[string]any {
	return map[string]any{
		"tag":      "wdns-direct",
		"protocol": "freedom",
		"settings": map[string]any{},
	}
}

func outboundBlocked() map[string]any {
	return map[string]any{
		"tag":      "wdns-blocked",
		"protocol": "blackhole",
		"settings": map[string]any{},
	}
}

func outboundTor() map[string]any {
	return map[string]any{
		"tag":      "wdns-tor",
		"protocol": "socks",
		"settings": map[string]any{
			"servers": []map[string]any{
				{
					"address": "tor",
					"port":    9050,
					"users":   []any{},
				},
			},
		},
	}
}

func marshalJSON(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}
