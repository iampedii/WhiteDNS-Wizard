package xui

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/whitedns/wdns-wizard/internal/planner"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

func testProtocolValues() map[string]string {
	return map[string]string{
		"vless_uuid":                      "11111111-1111-1111-1111-111111111111",
		"vless_8443_uuid":                 "44444444-4444-4444-4444-444444444444",
		"direct_vless_uuid":               "22222222-2222-2222-2222-222222222222",
		"reality_vless_uuid":              "33333333-3333-3333-3333-333333333333",
		"reality_private_key":             "reality-private",
		"reality_public_key":              "reality-public",
		"reality_short_id":                "a1b2c3d4",
		"reality_mldsa65_seed":            "reality-seed",
		"reality_mlkem_decryption":        "mlkem768x25519plus.native.600s.decrypt",
		"reality_mlkem_encryption":        "mlkem768x25519plus.native.0rtt.encrypt",
		"reality_sni":                     "digikala.com",
		"trojan_password":                 "trojan-secret",
		"hysteria2_password":              "hy-secret",
		"hysteria2_obfs_password":         "hy-obfs-secret",
		"shadowsocks_server_password":     "ss-server-secret",
		"shadowsocks_client_password":     "ss-client-secret",
		"tor_vless_uuid":                  "55555555-5555-5555-5555-555555555555",
		"tor_vless_8443_uuid":             "66666666-6666-6666-6666-666666666666",
		"tor_direct_vless_uuid":           "77777777-7777-7777-7777-777777777777",
		"tor_reality_vless_uuid":          "88888888-8888-8888-8888-888888888888",
		"tor_reality_private_key":         "tor-reality-private",
		"tor_reality_public_key":          "tor-reality-public",
		"tor_reality_short_id":            "b2c3d4e5",
		"tor_reality_mldsa65_seed":        "tor-reality-seed",
		"tor_reality_mlkem_decryption":    "mlkem768x25519plus.native.600s.tor-decrypt",
		"tor_reality_mlkem_encryption":    "mlkem768x25519plus.native.0rtt.tor-encrypt",
		"tor_reality_sni":                 "www.microsoft.com",
		"tor_hysteria2_password":          "tor-hy-secret",
		"tor_hysteria2_obfs_password":     "tor-hy-obfs-secret",
		"tor_shadowsocks_server_password": "tor-ss-server-secret",
		"tor_shadowsocks_client_password": "tor-ss-client-secret",
		"vless_ws_path":                   "/tp-vless",
		"trojan_ws_path":                  "/tp-trojan",
	}
}

func TestBuildProtocolBundleCreatesTwelveClientLinks(t *testing.T) {
	bundle, err := BuildProtocolBundle("example.com", testProtocolValues())
	if err != nil {
		t.Fatalf("BuildProtocolBundle returned error: %v", err)
	}
	if len(bundle.Inbounds) != 12 {
		t.Fatalf("inbounds = %d, want 12", len(bundle.Inbounds))
	}
	if len(bundle.Links.Clients) != 12 {
		t.Fatalf("links = %d, want 12", len(bundle.Links.Clients))
	}
	assertContains(t, bundle.Links.Clients[0].Link, "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443")
	assertContains(t, bundle.Links.Clients[0].Link, "?type=ws&security=tls&encryption=none")
	assertContains(t, bundle.Links.Clients[0].Link, "#VLESS%20WS%20")
	assertContains(t, bundle.Links.Clients[1].Link, "vless://44444444-4444-4444-4444-444444444444@trojan.example.com:8443")
	assertContains(t, bundle.Links.Clients[1].Link, "?type=ws&security=tls&encryption=none")
	assertContains(t, bundle.Links.Clients[1].Link, "#VLESS%20WS%208443%20")
	assertContains(t, bundle.Links.Clients[2].Link, "hysteria2://hy-secret@hy2.example.com:443")
	assertContains(t, bundle.Links.Clients[2].Link, "?sni=hy2.example.com&alpn=h3")
	assertContains(t, bundle.Links.Clients[2].Link, "obfs=salamander")
	assertContains(t, bundle.Links.Clients[2].Link, "obfs-password=hy-obfs-secret")
	assertContains(t, bundle.Links.Clients[2].Link, "#Hysteria2%20")
	assertContains(t, bundle.Links.Clients[3].Link, "vless://22222222-2222-2222-2222-222222222222@direct.example.com:2087")
	assertContains(t, bundle.Links.Clients[3].Link, "?type=tcp&security=tls&encryption=none")
	assertContains(t, bundle.Links.Clients[3].Link, "#Direct%20VLESS%20")
	realityLink := bundle.Links.Clients[4].Link
	assertContains(t, realityLink, "vless://33333333-3333-3333-3333-333333333333@reality.example.com:2083")
	assertContains(t, realityLink, "?type=xhttp&security=reality&encryption=none")
	assertContains(t, realityLink, "pbk=reality-public")
	assertContains(t, realityLink, "sid=a1b2c3d4")
	assertContains(t, realityLink, "sni=digikala.com")
	assertContains(t, realityLink, "#Reality%20XHTTP%20")
	shadowsocksLink := bundle.Links.Clients[5].Link
	assertContains(t, shadowsocksLink, "ss://")
	assertContains(t, shadowsocksLink, "@ss.example.com:8388?type=tcp#Shadowsocks%20")
	encodedSS := strings.TrimPrefix(strings.Split(shadowsocksLink, "@")[0], "ss://")
	decodedSS, err := base64.RawURLEncoding.DecodeString(encodedSS)
	if err != nil {
		t.Fatalf("decode shadowsocks link: %v", err)
	}
	if string(decodedSS) != "2022-blake3-aes-256-gcm:ss-server-secret:ss-client-secret" {
		t.Fatalf("decoded shadowsocks link = %q", decodedSS)
	}
	torVLESSLink := bundle.Links.Clients[6].Link
	assertContains(t, torVLESSLink, "vless://55555555-5555-5555-5555-555555555555@tor-vless-ws.example.com:2097")
	assertContains(t, torVLESSLink, "#VLESS%20WS%20Tor%20")
	torVLESS8443Link := bundle.Links.Clients[7].Link
	assertContains(t, torVLESS8443Link, "vless://66666666-6666-6666-6666-666666666666@tor-vless-ws-8443.example.com:2098")
	assertContains(t, torVLESS8443Link, "#VLESS%20WS%208443%20Tor%20")
	torHy2Link := bundle.Links.Clients[8].Link
	assertContains(t, torHy2Link, "hysteria2://tor-hy-secret@tor-hy2.example.com:2099")
	assertContains(t, torHy2Link, "obfs-password=tor-hy-obfs-secret")
	assertContains(t, torHy2Link, "#Hysteria2%20Tor%20")
	torDirectLink := bundle.Links.Clients[9].Link
	assertContains(t, torDirectLink, "vless://77777777-7777-7777-7777-777777777777@tor-direct.example.com:2100")
	assertContains(t, torDirectLink, "#Direct%20VLESS%20Tor%20")
	torRealityLink := bundle.Links.Clients[10].Link
	assertContains(t, torRealityLink, "vless://88888888-8888-8888-8888-888888888888@tor-reality.example.com:2101")
	assertContains(t, torRealityLink, "pbk=tor-reality-public")
	assertContains(t, torRealityLink, "sni=www.microsoft.com")
	assertContains(t, torRealityLink, "#Reality%20XHTTP%20Tor%20")
	torShadowsocksLink := bundle.Links.Clients[11].Link
	assertContains(t, torShadowsocksLink, "@tor-ss.example.com:8390?type=tcp#Shadowsocks%20Tor%20")
	encodedTorSS := strings.TrimPrefix(strings.Split(torShadowsocksLink, "@")[0], "ss://")
	decodedTorSS, err := base64.RawURLEncoding.DecodeString(encodedTorSS)
	if err != nil {
		t.Fatalf("decode tor shadowsocks link: %v", err)
	}
	if string(decodedTorSS) != "2022-blake3-aes-256-gcm:tor-ss-server-secret:tor-ss-client-secret" {
		t.Fatalf("decoded tor shadowsocks link = %q", decodedTorSS)
	}

	vless8443 := inboundByTag(t, bundle.Inbounds, "wdns-vless-ws-8443")
	if vless8443.Protocol != "vless" || vless8443.Port != 8443 {
		t.Fatalf("unexpected 8443 vless inbound: %+v", vless8443)
	}
	vless8443WS, _ := vless8443.StreamSettings["wsSettings"].(map[string]any)
	if _, hasHeaders := vless8443WS["headers"]; hasHeaders {
		t.Fatalf("wsSettings should not include deprecated headers.Host: %+v", vless8443WS)
	}
	vless8443Sockopt, _ := vless8443.StreamSettings["sockopt"].(map[string]any)
	if got := fmt.Sprint(vless8443Sockopt["trustedXForwardedFor"]); got != "[WhiteDNS-No-Trusted-XFF]" {
		t.Fatalf("ws inbounds should explicitly disable trustedXForwardedFor: %+v", vless8443.StreamSettings)
	}

	hysteria2 := inboundByTag(t, bundle.Inbounds, "wdns-hysteria2")
	clients, ok := hysteria2.Settings["clients"].([]map[string]any)
	if !ok || len(clients) != 1 {
		t.Fatalf("hysteria2 should use settings.clients: %+v", hysteria2.Settings)
	}
	if _, hasUsers := hysteria2.Settings["users"]; hasUsers {
		t.Fatalf("hysteria2 should not use settings.users in 3x-ui API payloads: %+v", hysteria2.Settings)
	}
	if clients[0]["auth"] != "hy-secret" || clients[0]["email"] != "WhiteDNS-hy2-example-com" || clients[0]["enable"] != true || clients[0]["subId"] == "" {
		t.Fatalf("unexpected hysteria2 client: %+v", clients[0])
	}
	for _, key := range []string{"limitIp", "totalGB", "expiryTime", "tgId", "reset"} {
		if clients[0][key] != 0 {
			t.Fatalf("unexpected hysteria2 client %s: %+v", key, clients[0])
		}
	}
	hysteriaSettings, _ := hysteria2.StreamSettings["hysteriaSettings"].(map[string]any)
	if hysteriaSettings["auth"] != "hy-secret" {
		t.Fatalf("hysteriaSettings.auth = %q, want hy-secret", hysteriaSettings["auth"])
	}
	hysteriaTLS, _ := hysteria2.StreamSettings["tlsSettings"].(map[string]any)
	if got := fmt.Sprint(hysteriaTLS["alpn"]); got != "[h3]" {
		t.Fatalf("hysteria2 TLS ALPN = %s, want [h3]", got)
	}
	finalmask, _ := hysteria2.StreamSettings["finalmask"].(map[string]any)
	udp, _ := finalmask["udp"].([]map[string]any)
	if len(udp) != 1 || udp[0]["type"] != "salamander" {
		t.Fatalf("unexpected hysteria2 finalmask udp: %+v", finalmask)
	}
	obfsSettings, _ := udp[0]["settings"].(map[string]any)
	if obfsSettings["password"] != "hy-obfs-secret" {
		t.Fatalf("unexpected hysteria2 obfs settings: %+v", obfsSettings)
	}
	quicParams, _ := finalmask["quicParams"].(map[string]any)
	if quicParams["congestion"] != "bbr" {
		t.Fatalf("unexpected hysteria2 quic params: %+v", quicParams)
	}

	reality := inboundByTag(t, bundle.Inbounds, "wdns-reality-xhttp")
	if reality.Protocol != "vless" || reality.Port != 2083 {
		t.Fatalf("unexpected reality inbound: %+v", reality)
	}
	if reality.Settings["decryption"] != "none" {
		t.Fatalf("unexpected reality vless settings: %+v", reality.Settings)
	}
	if _, hasEncryption := reality.Settings["encryption"]; hasEncryption {
		t.Fatalf("reality settings should not include unmatched VLESS encryption: %+v", reality.Settings)
	}
	stream := reality.StreamSettings
	if stream["network"] != "xhttp" || stream["security"] != "reality" {
		t.Fatalf("unexpected reality stream settings: %+v", stream)
	}
	realitySettings, _ := stream["realitySettings"].(map[string]any)
	if realitySettings["target"] != "digikala.com:443" || realitySettings["privateKey"] != "reality-private" {
		t.Fatalf("unexpected reality settings: %+v", realitySettings)
	}
	if got := fmt.Sprint(realitySettings["serverNames"]); got != "[digikala.com]" {
		t.Fatalf("unexpected reality serverNames: %+v", realitySettings)
	}
	xhttpSettings, _ := stream["xhttpSettings"].(map[string]any)
	if xhttpSettings["path"] != "/" || xhttpSettings["mode"] != "auto" {
		t.Fatalf("unexpected xhttp settings: %+v", xhttpSettings)
	}
	realitySockopt, _ := stream["sockopt"].(map[string]any)
	if got := fmt.Sprint(realitySockopt["trustedXForwardedFor"]); got != "[WhiteDNS-No-Trusted-XFF]" {
		t.Fatalf("reality xhttp should explicitly disable trustedXForwardedFor: %+v", stream)
	}

	shadowsocks := inboundByTag(t, bundle.Inbounds, "wdns-shadowsocks")
	if shadowsocks.Protocol != "shadowsocks" || shadowsocks.Port != 8388 {
		t.Fatalf("unexpected shadowsocks inbound: %+v", shadowsocks)
	}
	if shadowsocks.Settings["method"] != "2022-blake3-aes-256-gcm" || shadowsocks.Settings["password"] != "ss-server-secret" || shadowsocks.Settings["network"] != "tcp,udp" {
		t.Fatalf("unexpected shadowsocks settings: %+v", shadowsocks.Settings)
	}
	ssClients, ok := shadowsocks.Settings["clients"].([]map[string]any)
	if !ok || len(ssClients) != 1 {
		t.Fatalf("shadowsocks should use settings.clients: %+v", shadowsocks.Settings)
	}
	if ssClients[0]["password"] != "ss-client-secret" || ssClients[0]["email"] != "WhiteDNS-ss-example-com" || ssClients[0]["enable"] != true || ssClients[0]["subId"] == "" {
		t.Fatalf("unexpected shadowsocks client: %+v", ssClients[0])
	}
	for _, key := range []string{"limitIp", "totalGB", "expiryTime", "tgId", "reset"} {
		if ssClients[0][key] != 0 {
			t.Fatalf("unexpected shadowsocks client %s: %+v", key, ssClients[0])
		}
	}
	ssStream := shadowsocks.StreamSettings
	if ssStream["network"] != "tcp" || ssStream["security"] != "none" {
		t.Fatalf("unexpected shadowsocks stream settings: %+v", ssStream)
	}

	torVLESS := inboundByTag(t, bundle.Inbounds, "wdns-tor-vless-ws")
	if torVLESS.Protocol != "vless" || torVLESS.Port != 2097 {
		t.Fatalf("unexpected tor vless inbound: %+v", torVLESS)
	}
	torVLESSStream := torVLESS.StreamSettings
	if torVLESSStream["network"] != "ws" || torVLESSStream["security"] != "tls" {
		t.Fatalf("unexpected tor vless stream: %+v", torVLESSStream)
	}
	torVLESSTLS, _ := torVLESSStream["tlsSettings"].(map[string]any)
	torVLESSCerts, _ := torVLESSTLS["certificates"].([]map[string]any)
	if len(torVLESSCerts) != 1 || torVLESSCerts[0]["certificateFile"] != RemotePublicCertPath {
		t.Fatalf("tor vless should use public ACME cert: %+v", torVLESSTLS)
	}

	torHysteria := inboundByTag(t, bundle.Inbounds, "wdns-tor-hysteria2")
	if torHysteria.Protocol != "hysteria" || torHysteria.Port != 2099 {
		t.Fatalf("unexpected tor hysteria inbound: %+v", torHysteria)
	}
	torHysteriaSettings, _ := torHysteria.StreamSettings["hysteriaSettings"].(map[string]any)
	if torHysteriaSettings["auth"] != "tor-hy-secret" {
		t.Fatalf("unexpected tor hysteria auth: %+v", torHysteriaSettings)
	}

	torReality := inboundByTag(t, bundle.Inbounds, "wdns-tor-reality-xhttp")
	torRealitySettings, _ := torReality.StreamSettings["realitySettings"].(map[string]any)
	if torRealitySettings["privateKey"] != "tor-reality-private" {
		t.Fatalf("unexpected tor reality settings: %+v", torRealitySettings)
	}
	if torRealitySettings["target"] != "www.microsoft.com:443" {
		t.Fatalf("unexpected tor reality target: %+v", torRealitySettings)
	}

	torShadowsocks := inboundByTag(t, bundle.Inbounds, "wdns-tor-shadowsocks")
	if torShadowsocks.Protocol != "shadowsocks" || torShadowsocks.Port != 8390 {
		t.Fatalf("unexpected tor shadowsocks inbound: %+v", torShadowsocks)
	}
	if torShadowsocks.Settings["password"] != "tor-ss-server-secret" {
		t.Fatalf("unexpected tor shadowsocks settings: %+v", torShadowsocks.Settings)
	}
}

func TestRenderComposePublishesRequiredPorts(t *testing.T) {
	compose := RenderCompose("pg-secret")
	for _, want := range []string{
		`"2053:2053/tcp"`,
		`"443:443/tcp"`,
		`"443:443/udp"`,
		`"8443:8443/tcp"`,
		`"2087:2087/tcp"`,
		`"2083:2083/tcp"`,
		`"8388:8388/tcp"`,
		`"8388:8388/udp"`,
		`"2097:2097/tcp"`,
		`"2098:2098/tcp"`,
		`"2099:2099/udp"`,
		`"2100:2100/tcp"`,
		`"2101:2101/tcp"`,
		`"8390:8390/tcp"`,
		`"8390:8390/udp"`,
		`"8080:8080/tcp"`,
		`"56201:56201/tcp"`,
		`"56207:56207/tcp"`,
		`container_name: 3xui_tor`,
		`context: ./tor`,
		`XUI_DB_TYPE: "postgres"`,
		`postgres://xui:pg-secret@postgres:5432/xui?sslmode=disable`,
	} {
		assertContains(t, compose, want)
	}
	if strings.Contains(compose, "9050:9050") {
		t.Fatalf("compose should not publish Tor SOCKS port:\n%s", compose)
	}
}

func TestEnsureOutboundsAddsTorOutboundAndRouting(t *testing.T) {
	config := map[string]any{
		"outbounds": []any{
			map[string]any{"tag": "user-out", "protocol": "freedom"},
			map[string]any{"tag": "wdns-tor", "protocol": "socks"},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "outboundTag": "user-out", "domain": []any{"domain:example.com"}},
				map[string]any{"type": "field", "outboundTag": "wdns-tor", "inboundTag": []any{"old"}},
			},
		},
	}
	config = EnsureOutbounds(config)
	if !torOutboundPresent(config) {
		t.Fatalf("tor outbound missing: %+v", config["outbounds"])
	}
	if missing := missingTorRoutingTags(config); len(missing) != 0 {
		t.Fatalf("missing tor routing tags: %+v", missing)
	}
	var torOutboundCount int
	for _, outbound := range outbounds(config) {
		if outbound["tag"] == "wdns-tor" {
			torOutboundCount++
		}
	}
	if torOutboundCount != 1 {
		t.Fatalf("tor outbound count = %d, want 1: %+v", torOutboundCount, config["outbounds"])
	}
}

func TestRemoveManagedOutboundsRemovesTorRouting(t *testing.T) {
	config := EnsureOutbounds(map[string]any{
		"outbounds": []any{map[string]any{"tag": "user-out", "protocol": "freedom"}},
	})
	config = RemoveManagedOutbounds(config)
	for _, outbound := range outbounds(config) {
		if isManagedOutboundTag(fmt.Sprint(outbound["tag"])) {
			t.Fatalf("managed outbound remained: %+v", outbounds(config))
		}
	}
	if missing := missingTorRoutingTags(config); len(missing) != len(torInboundTags()) {
		t.Fatalf("tor routing should be removed, missing = %+v", missing)
	}
}

func TestDetectConflictsFindsPortTagOutboundAndClient(t *testing.T) {
	bundle, err := BuildProtocolBundle("example.com", testProtocolValues())
	if err != nil {
		t.Fatalf("BuildProtocolBundle returned error: %v", err)
	}
	existing := []Inbound{
		{ID: 1, Port: 443, Tag: "other-443", Settings: map[string]any{}},
		{ID: 2, Port: 9000, Tag: "wdns-vless-ws-8443", Settings: map[string]any{}},
		{ID: 3, Port: 9001, Tag: "other-client", Settings: map[string]any{"clients": []any{map[string]any{"email": "wdns-direct-example-com"}}}},
	}
	config := map[string]any{"outbounds": []any{
		map[string]any{"tag": "wdns-direct", "protocol": "freedom"},
		map[string]any{"tag": "wdns-tor", "protocol": "socks"},
	}}
	conflicts := DetectConflicts(existing, config, bundle.Inbounds)
	if len(conflicts) < 4 {
		t.Fatalf("conflicts = %+v, want at least 4", conflicts)
	}
	kinds := strings.Join([]string{conflicts[0].Kind, conflicts[1].Kind, conflicts[2].Kind, conflicts[3].Kind}, ",")
	for _, want := range []string{"port", "inbound", "client", "outbound"} {
		assertContains(t, kinds, want)
	}
}

const iranTestUUID = "55555555-5555-5555-5555-555555555555"

func iranXHTTPProto(front, cdnHost string, port int) types.Protocol {
	return types.Protocol{
		Name:       "iran_xhttp_tls",
		Profile:    "iran-domestic",
		Hostname:   cdnHost,
		Address:    cdnHost,
		Host:       front,
		ServerName: front,
		Port:       port,
		Network:    "xhttp",
		Transport:  "xhttp",
		Security:   "tls",
		TLS:        true,
		Tag:        "wdns-iran-xhttp-cdn",
		Path:       "/",
		Extra:      `{"scMaxEachPostBytes":1000000,"scMinPostsIntervalMs":30,"xPaddingBytes":"100-1000","noGRPCHeader":false}`,
	}
}

func iranWSProto(front, address string, port int) types.Protocol {
	return types.Protocol{
		Name:      "iran_ws_none",
		Profile:   "iran-domestic",
		Hostname:  address,
		Address:   address,
		Host:      front,
		Port:      port,
		Network:   "ws",
		Transport: "ws",
		Security:  "none",
		Tag:       "wdns-iran-ws-cdn",
		Path:      "/filmonline?ed=2048",
	}
}

func iranTCPProto(address string, port int) types.Protocol {
	return types.Protocol{
		Name:       "iran_tcp_http",
		Profile:    "iran-domestic",
		Hostname:   address,
		Address:    address,
		Port:       port,
		Network:    "tcp",
		Transport:  "tcp",
		Security:   "none",
		HeaderType: "http",
		Tag:        "wdns-iran-tcp-http",
		Path:       "/",
	}
}

func iranTestValues() map[string]string {
	return map[string]string{
		"iran_xhttp_uuid": iranTestUUID,
		"iran_ws_uuid":    "66666666-6666-6666-6666-666666666666",
		"iran_tcp_uuid":   "77777777-7777-7777-7777-777777777777",
		"iran_ws_path":    "/filmonline?ed=2048",
	}
}

func buildIranBundle(t *testing.T) ProtocolBundle {
	t.Helper()
	bundle, err := BuildIranProtocolBundle("example.com", planner.IranFrontingInput{
		Front:     "setup.azargate.ir",
		CDNHost:   "cdn2.navaanet.ir",
		CDNPort:   2053,
		WSFront:   "domain.iran243.ir",
		WSAddress: "snapp.ir",
		WSPort:    8880,
		TCPHost:   "edge.nextgen.ir",
		TCPPort:   56206,
	}, iranTestValues())
	if err != nil {
		t.Fatalf("BuildIranProtocolBundle returned error: %v", err)
	}
	return bundle
}

func TestIranXHTTPLink(t *testing.T) {
	link := iranXHTTPLink(iranXHTTPProto("setup.azargate.ir", "cdn2.navaanet.ir", 2053), iranTestUUID)
	assertContains(t, link, "vless://55555555-5555-5555-5555-555555555555@cdn2.navaanet.ir:2053")
	assertContains(t, link, "?type=xhttp&security=tls&encryption=none")
	assertContains(t, link, "host=setup.azargate.ir")
	assertContains(t, link, "sni=setup.azargate.ir")
	assertContains(t, link, "fp=chrome")
	assertContains(t, link, "alpn=h2%2Chttp%2F1.1")
	assertContains(t, link, "%22scMaxEachPostBytes%22%3A1000000")
	if strings.Contains(link, "+") {
		t.Fatal("extra must not contain '+' (v2rayN parse bug)")
	}
	if strings.Contains(link, "scMaxConcurrentPosts") {
		t.Fatal("dead field must not be emitted")
	}
	assertContains(t, link, "#Iran%20CDN%20XHTTP%20%40whiteDNS")
}

func TestEscapeQueryValueExtraUsesPercent20NotPlus(t *testing.T) {
	// A space inside any non-extra value escapes to '+', matching legacy behaviour.
	if got := escapeQueryValue("path", "a b"); got != "a+b" {
		t.Fatalf("non-extra space = %q, want a+b", got)
	}
	// A space inside extra= must become %20 (never the raw '+' that breaks v2rayN).
	if got := escapeQueryValue("extra", `{"k": 1}`); strings.Contains(got, "+") {
		t.Fatalf("extra value must not contain '+': %q", got)
	}
	if got := escapeQueryValue("extra", `{"k": 1}`); !strings.Contains(got, "%20") {
		t.Fatalf("extra space must be %%20-encoded: %q", got)
	}
	// A literal '+' inside extra= survives as %2B and is left untouched.
	if got := escapeQueryValue("extra", "a+b"); got != "a%2Bb" {
		t.Fatalf("literal '+' in extra = %q, want a%%2Bb", got)
	}
}

func TestIranWSLink(t *testing.T) {
	link := iranWSLink(iranWSProto("domain.iran243.ir", "snapp.ir", 8880), iranTestUUID)
	assertContains(t, link, "@snapp.ir:8880")
	assertContains(t, link, "?type=ws&security=none&encryption=none")
	assertContains(t, link, "host=domain.iran243.ir")
	if strings.Contains(link, "sni=") {
		t.Fatal("ws-none must not emit sni")
	}
	assertContains(t, link, "%2Ffilmonline%3Fed%3D2048")
}

func TestIranTCPHTTPLink(t *testing.T) {
	link := iranTCPHTTPLink(iranTCPProto("edge.nextgen.ir", 56206), iranTestUUID)
	assertContains(t, link, "@edge.nextgen.ir:56206")
	assertContains(t, link, "?type=tcp&security=none&encryption=none&headerType=http")
}

func TestIranXHTTPInboundShape(t *testing.T) {
	inbounds := buildIranBundle(t).Inbounds
	in := inboundByTag(t, inbounds, "wdns-iran-xhttp-cdn")
	ss := in.StreamSettings
	if ss["security"] != "none" {
		t.Fatalf("origin XHTTP must be security=none, got %v", ss["security"])
	}
	if _, hasReality := ss["realitySettings"]; hasReality {
		t.Fatal("must NOT carry realitySettings")
	}
	xh := ss["xhttpSettings"].(map[string]any)
	if xh["host"] != "setup.azargate.ir" {
		t.Fatalf("xhttp host = %v, want setup.azargate.ir", xh["host"])
	}
	if xh["scMaxBufferedPosts"] != 30 {
		t.Fatalf("scMaxBufferedPosts = %v, want 30", xh["scMaxBufferedPosts"])
	}
	if _, hasDead := xh["scMaxConcurrentPosts"]; hasDead {
		t.Fatal("dead scMaxConcurrentPosts must not be emitted server-side")
	}
	if in.Sniffing["enabled"] != false {
		t.Fatal("sniffing must be disabled")
	}
}

func TestIranWSInboundShape(t *testing.T) {
	in := inboundByTag(t, buildIranBundle(t).Inbounds, "wdns-iran-ws-cdn")
	ss := in.StreamSettings
	if ss["security"] != "none" {
		t.Fatalf("ws security = %v, want none", ss["security"])
	}
	if _, has := ss["tlsSettings"]; has {
		t.Fatal("ws-none must not carry tlsSettings")
	}
	ws := ss["wsSettings"].(map[string]any)
	if ws["path"] != "/filmonline" {
		t.Fatalf("server ws path = %v, want /filmonline (strips ?ed=)", ws["path"])
	}
	if ws["host"] != "domain.iran243.ir" {
		t.Fatalf("ws host = %v, want domain.iran243.ir", ws["host"])
	}
}

func TestIranTCPInboundShape(t *testing.T) {
	in := inboundByTag(t, buildIranBundle(t).Inbounds, "wdns-iran-tcp-http")
	ss := in.StreamSettings
	if ss["network"] != "tcp" || ss["security"] != "none" {
		t.Fatalf("unexpected tcp stream: %+v", ss)
	}
	tcp := ss["tcpSettings"].(map[string]any)
	header := tcp["header"].(map[string]any)
	if header["type"] != "http" {
		t.Fatalf("tcp header type = %v, want http", header["type"])
	}
}

func TestBuildIranProtocolBundleCreatesThreeProfiles(t *testing.T) {
	bundle := buildIranBundle(t)
	if len(bundle.Inbounds) != 3 {
		t.Fatalf("iran inbounds = %d, want 3", len(bundle.Inbounds))
	}
	if len(bundle.Links.Clients) != 3 {
		t.Fatalf("iran links = %d, want 3", len(bundle.Links.Clients))
	}
	for _, proto := range bundle.Plan.Protocols {
		if proto.Profile != "iran-domestic" {
			t.Fatalf("profile = %q, want iran-domestic", proto.Profile)
		}
	}
}

func TestBuildIranProtocolBundleRejectsBadFront(t *testing.T) {
	_, err := BuildIranProtocolBundle("example.com", planner.IranFrontingInput{
		Front:   "front-a.ir",
		CDNHost: "cdn.example.ir",
		WSFront: "front.ir", WSAddress: "front.ir", // address == host -> invalid
	}, iranTestValues())
	if err == nil {
		t.Fatal("expected validation error for ws address == host")
	}
}

func inboundByTag(t *testing.T, inbounds []Inbound, tag string) Inbound {
	t.Helper()
	for _, inbound := range inbounds {
		if inbound.Tag == tag {
			return inbound
		}
	}
	t.Fatalf("inbound %q not found in %+v", tag, inbounds)
	return Inbound{}
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("%q did not contain %q", got, want)
	}
}
