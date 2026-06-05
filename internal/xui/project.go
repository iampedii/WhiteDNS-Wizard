package xui

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/whitedns/wdns-wizard/internal/output"
	"github.com/whitedns/wdns-wizard/internal/planner"
	"github.com/whitedns/wdns-wizard/internal/secrets"
	"gopkg.in/yaml.v3"
)

type projectData struct {
	Root    string
	Domain  string
	Paths   output.ProjectPaths
	Secrets map[string]string
}

func loadProject(root, domain string) (projectData, error) {
	normalized, err := planner.NormalizeDomain(domain)
	if err != nil {
		return projectData{}, err
	}
	if strings.TrimSpace(root) == "" {
		root, err = output.DefaultRoot()
		if err != nil {
			return projectData{}, err
		}
	}
	paths := output.Paths(root, normalized)
	data, err := os.ReadFile(paths.Secrets)
	if err != nil {
		return projectData{}, fmt.Errorf("read project secrets %s: %w", paths.Secrets, err)
	}
	key, err := secrets.LoadOrCreateKey(filepath.Join(root, ".secrets.key"))
	if err != nil {
		return projectData{}, err
	}
	var envelope secrets.Envelope
	if err := yaml.Unmarshal(data, &envelope); err != nil {
		return projectData{}, fmt.Errorf("parse project secrets: %w", err)
	}
	values, err := secrets.DecryptMap(envelope, key)
	if err != nil {
		return projectData{}, err
	}
	return projectData{Root: root, Domain: normalized, Paths: paths, Secrets: values}, nil
}

func (p projectData) saveSecrets() error {
	key, err := secrets.LoadOrCreateKey(filepath.Join(p.Root, ".secrets.key"))
	if err != nil {
		return err
	}
	envelope, err := secrets.EncryptMap(p.Secrets, key)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal project secrets: %w", err)
	}
	if err := os.WriteFile(p.Paths.Secrets, data, 0o600); err != nil {
		return fmt.Errorf("write project secrets: %w", err)
	}
	return nil
}

func (p projectData) ensureXUISecrets(panel PanelCredentials) (bool, error) {
	changed := false
	generated, err := secrets.Generate()
	if err != nil {
		return false, err
	}
	defaults := map[string]string{
		"vless_8443_uuid":                 uuid.NewString(),
		"direct_vless_uuid":               uuid.NewString(),
		"reality_vless_uuid":              generated.RealityVLESSUUID,
		"reality_private_key":             generated.RealityPrivateKey,
		"reality_public_key":              generated.RealityPublicKey,
		"reality_short_id":                generated.RealityShortID,
		"reality_mldsa65_seed":            generated.RealityMLDSA65Seed,
		"reality_mlkem_decryption":        generated.RealityMLKEMDecryption,
		"reality_mlkem_encryption":        generated.RealityMLKEMEncryption,
		"reality_sni":                     generated.RealitySNI,
		"postgres_password":               generated.PostgresPassword,
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
		"iran_xhttp_uuid":                 generated.IranXHTTPUUID,
		"iran_ws_uuid":                    generated.IranWSUUID,
		"iran_tcp_uuid":                   generated.IranTCPUUID,
		"iran_ws_path":                    generated.IranWSPath,
	}
	for key, value := range defaults {
		if strings.TrimSpace(p.Secrets[key]) == "" {
			p.Secrets[key] = value
			changed = true
		}
	}
	if strings.TrimSpace(panel.Username) != "" {
		p.Secrets["panel_username"] = strings.TrimSpace(panel.Username)
		changed = true
	}
	if strings.TrimSpace(panel.Password) != "" {
		p.Secrets["panel_password"] = strings.TrimSpace(panel.Password)
		changed = true
	}
	if strings.TrimSpace(panel.WebBasePath) != "" {
		p.Secrets["panel_base_path"] = normalizeBasePath(panel.WebBasePath)
		changed = true
	}
	return changed, nil
}

func (p projectData) ensureGeneratedPanelCredentials() (bool, error) {
	if strings.TrimSpace(p.Secrets["panel_username"]) != "" &&
		strings.TrimSpace(p.Secrets["panel_password"]) != "" &&
		strings.TrimSpace(p.Secrets["panel_base_path"]) != "" {
		return false, nil
	}
	generated, err := secrets.Generate()
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(p.Secrets["panel_username"]) == "" {
		p.Secrets["panel_username"] = generated.PanelUsername
	}
	if strings.TrimSpace(p.Secrets["panel_password"]) == "" {
		p.Secrets["panel_password"] = generated.PanelPassword
	}
	if strings.TrimSpace(p.Secrets["panel_base_path"]) == "" {
		p.Secrets["panel_base_path"] = generated.PanelBasePath
	}
	return true, nil
}

func (p projectData) publicCertFresh(hostnames []string) bool {
	certPEM, err := os.ReadFile(p.Paths.PublicCert)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(p.Paths.PublicKey)
	if err != nil || len(strings.TrimSpace(string(keyPEM))) == 0 {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		return false
	}
	for _, hostname := range hostnames {
		if err := cert.VerifyHostname(hostname); err != nil {
			return false
		}
	}
	return true
}
