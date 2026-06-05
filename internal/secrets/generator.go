package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

type GeneratedSecrets struct {
	VLESSUUID              string `yaml:"vless_uuid"`
	VLESS8443UUID          string `yaml:"vless_8443_uuid"`
	DirectVLESSUUID        string `yaml:"direct_vless_uuid"`
	RealityVLESSUUID       string `yaml:"reality_vless_uuid"`
	RealityPrivateKey      string `yaml:"reality_private_key"`
	RealityPublicKey       string `yaml:"reality_public_key"`
	RealityShortID         string `yaml:"reality_short_id"`
	RealityMLDSA65Seed     string `yaml:"reality_mldsa65_seed"`
	RealityMLKEMDecryption string `yaml:"reality_mlkem_decryption"`
	RealityMLKEMEncryption string `yaml:"reality_mlkem_encryption"`
	RealitySNI             string `yaml:"reality_sni"`
	TrojanPassword         string `yaml:"trojan_password"`
	Hysteria2Password      string `yaml:"hysteria2_password"`
	Hysteria2ObfsPassword  string `yaml:"hysteria2_obfs_password"`
	ShadowsocksServerPass  string `yaml:"shadowsocks_server_password"`
	ShadowsocksClientPass  string `yaml:"shadowsocks_client_password"`
	TorVLESSUUID           string `yaml:"tor_vless_uuid"`
	TorVLESS8443UUID       string `yaml:"tor_vless_8443_uuid"`
	TorDirectVLESSUUID     string `yaml:"tor_direct_vless_uuid"`
	TorRealityVLESSUUID    string `yaml:"tor_reality_vless_uuid"`
	TorRealityPrivateKey   string `yaml:"tor_reality_private_key"`
	TorRealityPublicKey    string `yaml:"tor_reality_public_key"`
	TorRealityShortID      string `yaml:"tor_reality_short_id"`
	TorRealityMLDSA65Seed  string `yaml:"tor_reality_mldsa65_seed"`
	TorRealityMLKEMDecrypt string `yaml:"tor_reality_mlkem_decryption"`
	TorRealityMLKEMEncrypt string `yaml:"tor_reality_mlkem_encryption"`
	TorRealitySNI          string `yaml:"tor_reality_sni"`
	TorHysteria2Password   string `yaml:"tor_hysteria2_password"`
	TorHysteria2ObfsPass   string `yaml:"tor_hysteria2_obfs_password"`
	TorShadowsocksServer   string `yaml:"tor_shadowsocks_server_password"`
	TorShadowsocksClient   string `yaml:"tor_shadowsocks_client_password"`
	PanelUsername          string `yaml:"panel_username"`
	PanelPassword          string `yaml:"panel_password"`
	PanelBasePath          string `yaml:"panel_base_path"`
	PostgresPassword       string `yaml:"postgres_password"`
	VLESSWSPath            string `yaml:"vless_ws_path"`
	TrojanWSPath           string `yaml:"trojan_ws_path"`
	IranXHTTPUUID          string `yaml:"iran_xhttp_uuid"`
	IranWSUUID             string `yaml:"iran_ws_uuid"`
	IranTCPUUID            string `yaml:"iran_tcp_uuid"`
	IranWSPath             string `yaml:"iran_ws_path"`
}

func Generate() (GeneratedSecrets, error) {
	vlessPath, err := randomPath()
	if err != nil {
		return GeneratedSecrets{}, err
	}
	trojanPath, err := randomPath()
	if err != nil {
		return GeneratedSecrets{}, err
	}
	trojanPassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	hyPassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	hyObfsPassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	shadowsocksServerPass, err := randomBase64Token(32)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	shadowsocksClientPass, err := randomBase64Token(32)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torHyPassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torHyObfsPassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torShadowsocksServerPass, err := randomBase64Token(32)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torShadowsocksClientPass, err := randomBase64Token(32)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	panelPassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	postgresPassword, err := randomToken(24)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	panelUsername, err := randomToken(8)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	panelBasePath, err := randomPath()
	if err != nil {
		return GeneratedSecrets{}, err
	}
	realityPrivateKey, realityPublicKey, err := realityKeyPair()
	if err != nil {
		return GeneratedSecrets{}, err
	}
	realityShortID, err := randomHex(8)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	realityMLDSA65Seed, err := randomToken(32)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	realityMLKEMDecryption, err := realityMLKEMValue("600s")
	if err != nil {
		return GeneratedSecrets{}, err
	}
	realityMLKEMEncryption, err := realityMLKEMValue("0rtt")
	if err != nil {
		return GeneratedSecrets{}, err
	}
	realitySNI, err := randomRealitySNI()
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torRealityPrivateKey, torRealityPublicKey, err := realityKeyPair()
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torRealityShortID, err := randomHex(8)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torRealityMLDSA65Seed, err := randomToken(32)
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torRealityMLKEMDecryption, err := realityMLKEMValue("600s")
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torRealityMLKEMEncryption, err := realityMLKEMValue("0rtt")
	if err != nil {
		return GeneratedSecrets{}, err
	}
	torRealitySNI, err := randomRealitySNI()
	if err != nil {
		return GeneratedSecrets{}, err
	}

	return GeneratedSecrets{
		VLESSUUID:              uuid.NewString(),
		VLESS8443UUID:          uuid.NewString(),
		DirectVLESSUUID:        uuid.NewString(),
		RealityVLESSUUID:       uuid.NewString(),
		RealityPrivateKey:      realityPrivateKey,
		RealityPublicKey:       realityPublicKey,
		RealityShortID:         realityShortID,
		RealityMLDSA65Seed:     realityMLDSA65Seed,
		RealityMLKEMDecryption: realityMLKEMDecryption,
		RealityMLKEMEncryption: realityMLKEMEncryption,
		RealitySNI:             realitySNI,
		TrojanPassword:         trojanPassword,
		Hysteria2Password:      hyPassword,
		Hysteria2ObfsPassword:  hyObfsPassword,
		ShadowsocksServerPass:  shadowsocksServerPass,
		ShadowsocksClientPass:  shadowsocksClientPass,
		TorVLESSUUID:           uuid.NewString(),
		TorVLESS8443UUID:       uuid.NewString(),
		TorDirectVLESSUUID:     uuid.NewString(),
		TorRealityVLESSUUID:    uuid.NewString(),
		TorRealityPrivateKey:   torRealityPrivateKey,
		TorRealityPublicKey:    torRealityPublicKey,
		TorRealityShortID:      torRealityShortID,
		TorRealityMLDSA65Seed:  torRealityMLDSA65Seed,
		TorRealityMLKEMDecrypt: torRealityMLKEMDecryption,
		TorRealityMLKEMEncrypt: torRealityMLKEMEncryption,
		TorRealitySNI:          torRealitySNI,
		TorHysteria2Password:   torHyPassword,
		TorHysteria2ObfsPass:   torHyObfsPassword,
		TorShadowsocksServer:   torShadowsocksServerPass,
		TorShadowsocksClient:   torShadowsocksClientPass,
		PanelUsername:          "WhiteDNS-" + panelUsername[:8],
		PanelPassword:          panelPassword,
		PanelBasePath:          panelBasePath,
		PostgresPassword:       postgresPassword,
		VLESSWSPath:            vlessPath,
		TrojanWSPath:           trojanPath,
		IranXHTTPUUID:          uuid.NewString(),
		IranWSUUID:             uuid.NewString(),
		IranTCPUUID:            uuid.NewString(),
		IranWSPath:             DefaultIranWSPath,
	}, nil
}

func randomPath() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate websocket path: %w", err)
	}
	return "/tp-" + hex.EncodeToString(b[:]), nil
}

func randomToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomBase64Token(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func randomHex(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate hex secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func realityKeyPair() (string, string, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", fmt.Errorf("generate reality private key: %w", err)
	}
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("generate reality public key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(privateKey), base64.RawURLEncoding.EncodeToString(publicKey), nil
}

func realityMLKEMValue(mode string) (string, error) {
	value, err := randomToken(32)
	if err != nil {
		return "", err
	}
	return "mlkem768x25519plus.native." + mode + "." + value, nil
}

// DefaultIranWSPath is the WebSocket path (with client-only early data) used by
// the Iran WS-none domestic-fronting profile.
const DefaultIranWSPath = "/filmonline?ed=2048"

// iranFrontingCandidates are candidate .ir fronting hosts. SEED with the
// owner-controlled abshardejh.ir; the Example.txt tenant domains are other
// tenants' and WILL die — treat fronts as rotatable, validated at gen-time, and
// NEVER hardcode the Example.txt tenant domains as fixed truth. Operators append
// their own rotatable .ir fronts at runtime.
var iranFrontingCandidates = []string{
	"abshardejh.ir", // owner-controlled ArvanCloud (plan 1, NOT production) — safe default seed
}

// IranFrontingCandidates returns a copy of the seeded .ir fronting pool.
func IranFrontingCandidates() []string {
	return append([]string(nil), iranFrontingCandidates...)
}

// DefaultIranFront returns the default (owner-controlled) .ir fronting host.
func DefaultIranFront() string { return iranFrontingCandidates[0] }

func RealitySNICandidates() []string {
	return append([]string(nil), realitySNICandidates...)
}

func DefaultRealitySNI() string {
	return realitySNICandidates[0]
}

func randomRealitySNI() (string, error) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(realitySNICandidates))))
	if err != nil {
		return "", fmt.Errorf("choose reality sni: %w", err)
	}
	return realitySNICandidates[index.Int64()], nil
}

var realitySNICandidates = []string{
	"digikala.com",
	"aparat.com",
	"filimo.com",
	"divar.ir",
	"snapp.ir",
	"telewebion.com",
	"namnak.com",
	"varzesh3.com",
	"cafebazaar.ir",
	"snappfood.ir",
	"virgool.io",
	"torob.com",
	"mci.ir",
	"irancell.ir",
	"rightel.ir",
	"farhang.gov.ir",
	"nic.ir",
	"edu.sharif.edu",
	"iau.ac.ir",
	"ut.ac.ir",
	"isna.ir",
	"irna.ir",
	"www.google-analytics.com",
	"www.googletagmanager.com",
	"fonts.googleapis.com",
	"fonts.gstatic.com",
	"dl.google.com",
	"play.google.com",
	"www.google.com",
	"maps.googleapis.com",
	"www.microsoft.com",
	"www.bing.com",
	"learn.microsoft.com",
	"update.microsoft.com",
	"download.microsoft.com",
	"az764295.vo.msecnd.net",
	"www.apple.com",
	"swscan.apple.com",
	"mesu.apple.com",
	"updates.cdn-apple.com",
	"configuration.apple.com",
	"www.speedtest.net",
	"www.samsung.com",
	"www.asus.com",
	"www.amd.com",
	"www.cisco.com",
	"www.nvidia.com",
	"www.linksys.com",
	"www.hp.com",
	"www.dell.com",
	"www.lenovo.com",
	"www.xiaomi.com",
}

func PlaintextMap(token string, generated GeneratedSecrets, originPrivateKey string) map[string]string {
	return map[string]string{
		"cloudflare_token":                token,
		"origin_private_key":              originPrivateKey,
		"vless_uuid":                      generated.VLESSUUID,
		"vless_8443_uuid":                 generated.VLESS8443UUID,
		"direct_vless_uuid":               generated.DirectVLESSUUID,
		"reality_vless_uuid":              generated.RealityVLESSUUID,
		"reality_private_key":             generated.RealityPrivateKey,
		"reality_public_key":              generated.RealityPublicKey,
		"reality_short_id":                generated.RealityShortID,
		"reality_mldsa65_seed":            generated.RealityMLDSA65Seed,
		"reality_mlkem_decryption":        generated.RealityMLKEMDecryption,
		"reality_mlkem_encryption":        generated.RealityMLKEMEncryption,
		"reality_sni":                     generated.RealitySNI,
		"trojan_password":                 generated.TrojanPassword,
		"hysteria2_password":              generated.Hysteria2Password,
		"hysteria2_obfs_password":         generated.Hysteria2ObfsPassword,
		"shadowsocks_server_password":     generated.ShadowsocksServerPass,
		"shadowsocks_client_password":     generated.ShadowsocksClientPass,
		"tor_vless_uuid":                  generated.TorVLESSUUID,
		"tor_vless_8443_uuid":             generated.TorVLESS8443UUID,
		"tor_direct_vless_uuid":           generated.TorDirectVLESSUUID,
		"tor_reality_vless_uuid":          generated.TorRealityVLESSUUID,
		"tor_reality_private_key":         generated.TorRealityPrivateKey,
		"tor_reality_public_key":          generated.TorRealityPublicKey,
		"tor_reality_short_id":            generated.TorRealityShortID,
		"tor_reality_mldsa65_seed":        generated.TorRealityMLDSA65Seed,
		"tor_reality_mlkem_decryption":    generated.TorRealityMLKEMDecrypt,
		"tor_reality_mlkem_encryption":    generated.TorRealityMLKEMEncrypt,
		"tor_reality_sni":                 generated.TorRealitySNI,
		"tor_hysteria2_password":          generated.TorHysteria2Password,
		"tor_hysteria2_obfs_password":     generated.TorHysteria2ObfsPass,
		"tor_shadowsocks_server_password": generated.TorShadowsocksServer,
		"tor_shadowsocks_client_password": generated.TorShadowsocksClient,
		"panel_username":                  generated.PanelUsername,
		"panel_password":                  generated.PanelPassword,
		"panel_base_path":                 generated.PanelBasePath,
		"postgres_password":               generated.PostgresPassword,
		"vless_ws_path":                   generated.VLESSWSPath,
		"trojan_ws_path":                  generated.TrojanWSPath,
		"iran_xhttp_uuid":                 generated.IranXHTTPUUID,
		"iran_ws_uuid":                    generated.IranWSUUID,
		"iran_tcp_uuid":                   generated.IranTCPUUID,
		"iran_ws_path":                    generated.IranWSPath,
	}
}
