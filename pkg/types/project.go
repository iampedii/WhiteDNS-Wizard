package types

import "time"

const (
	SSLModeStrict = "strict"
	DefaultTTL    = 1
)

type DNSRecord struct {
	Name    string `json:"name" yaml:"name"`
	Type    string `json:"type" yaml:"type"`
	Content string `json:"content" yaml:"content"`
	Proxied bool   `json:"proxied" yaml:"proxied"`
	TTL     int    `json:"ttl" yaml:"ttl"`
	Purpose string `json:"purpose" yaml:"purpose"`
}

type DNSRecordStatus string

const (
	DNSRecordCreated   DNSRecordStatus = "CREATED"
	DNSRecordUpdated   DNSRecordStatus = "UPDATED"
	DNSRecordUnchanged DNSRecordStatus = "UNCHANGED"
	DNSRecordFailed    DNSRecordStatus = "FAILED"
)

type DNSRecordResult struct {
	Record DNSRecord       `json:"record" yaml:"record"`
	Status DNSRecordStatus `json:"status" yaml:"status"`
	ID     string          `json:"id,omitempty" yaml:"id,omitempty"`
	Error  string          `json:"error,omitempty" yaml:"error,omitempty"`
}

type Zone struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Status      string   `json:"status" yaml:"status"`
	NameServers []string `json:"name_servers" yaml:"name_servers"`
}

type OriginCertRequest struct {
	Hostnames         []string `json:"hostnames" yaml:"hostnames"`
	RequestType       string   `json:"request_type" yaml:"request_type"`
	RequestedValidity int      `json:"requested_validity" yaml:"requested_validity"`
	CSRPEM            string   `json:"-" yaml:"-"`
}

type OriginCert struct {
	ID             string `json:"id,omitempty" yaml:"id,omitempty"`
	CertificatePEM string `json:"certificate_pem" yaml:"certificate_pem"`
	PrivateKeyPEM  string `json:"-" yaml:"-"`
	ExpiresOn      string `json:"expires_on,omitempty" yaml:"expires_on,omitempty"`
}

type ProjectConfig struct {
	Project    string           `json:"project" yaml:"project"`
	ZoneID     string           `json:"zone_id" yaml:"zone_id"`
	VPSIP      string           `json:"vps_ip" yaml:"vps_ip"`
	Cloudflare CloudflareConfig `json:"cloudflare" yaml:"cloudflare"`
}

type CloudflareConfig struct {
	AccountID string      `json:"account_id,omitempty" yaml:"account_id,omitempty"`
	SSLMode   string      `json:"ssl_mode" yaml:"ssl_mode"`
	Records   []DNSRecord `json:"records" yaml:"records"`
}

type DNSPlan struct {
	Records []DNSRecord `json:"records" yaml:"records"`
}

type ProtocolPlan struct {
	Protocols []Protocol `json:"protocols" yaml:"protocols"`
}

type Protocol struct {
	Name              string `json:"name" yaml:"name"`
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	Hostname          string `json:"hostname" yaml:"hostname"`
	Port              int    `json:"port" yaml:"port"`
	Network           string `json:"network,omitempty" yaml:"network,omitempty"`
	Transport         string `json:"transport,omitempty" yaml:"transport,omitempty"`
	Tag               string `json:"tag,omitempty" yaml:"tag,omitempty"`
	ClientEmail       string `json:"client_email,omitempty" yaml:"client_email,omitempty"`
	Path              string `json:"path,omitempty" yaml:"path,omitempty"`
	TLS               bool   `json:"tls,omitempty" yaml:"tls,omitempty"`
	UDP               bool   `json:"udp,omitempty" yaml:"udp,omitempty"`
	CloudflareProxied bool   `json:"cloudflare_proxied" yaml:"cloudflare_proxied"`
	Certificate       string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	// --- TRACK A additions (Iran domestic-fronting) ---
	Address    string `json:"address,omitempty" yaml:"address,omitempty"`         // connect authority: CDN edge host/IP. Fallback: Hostname
	ServerName string `json:"server_name,omitempty" yaml:"server_name,omitempty"` // TLS SNI; only when TLS=true; empty for WS-none. Fallback: Hostname
	Host       string `json:"host,omitempty" yaml:"host,omitempty"`               // HTTP Host header (the .ir front). Fallback: ServerName(TLS) else Address
	Profile    string `json:"profile,omitempty" yaml:"profile,omitempty"`         // "" (global/cloudflare) | "iran-domestic"
	Security   string `json:"security,omitempty" yaml:"security,omitempty"`       // "tls" | "none" | "reality" (override; defaults from TLS bool)
	HeaderType string `json:"header_type,omitempty" yaml:"header_type,omitempty"` // "http" for TCP camouflage profile
	Extra      string `json:"extra,omitempty" yaml:"extra,omitempty"`             // minified XHTTP extra JSON (client link)
	CertMode   string `json:"cert_mode,omitempty" yaml:"cert_mode,omitempty"`     // "cloudflare-origin-ca" | "self-signed" | "origin-http"
}

// ResolvedAddress returns the connect authority for the client link, falling
// back to the legacy Hostname when Address is unset.
func (p Protocol) ResolvedAddress() string {
	if p.Address != "" {
		return p.Address
	}
	return p.Hostname
}

// ResolvedServerName returns the TLS SNI, falling back to Hostname.
func (p Protocol) ResolvedServerName() string {
	if p.ServerName != "" {
		return p.ServerName
	}
	return p.Hostname
}

// ResolvedHost returns the HTTP Host header: explicit Host first, then the SNI
// (for TLS profiles) and finally the connect address.
func (p Protocol) ResolvedHost() string {
	if p.Host != "" {
		return p.Host
	}
	if p.TLS {
		return p.ResolvedServerName()
	}
	return p.ResolvedAddress()
}

type ProvisionInput struct {
	Token     string
	AccountID string
	Domain    string
	VPSIP     string
	Root      string
}

type ProvisionResult struct {
	ProjectDir   string
	Zone         Zone
	DNSResults   []DNSRecordResult
	OriginCert   OriginCert
	Config       ProjectConfig
	DNSPlan      DNSPlan
	ProtocolPlan ProtocolPlan
}

type CloudflareState struct {
	Zone         Zone              `json:"zone"`
	DNSResults   []DNSRecordResult `json:"dns_results"`
	OriginCertID string            `json:"origin_cert_id,omitempty"`
	AppliedAt    time.Time         `json:"applied_at"`
}

type XUIPlan struct {
	Domain          string        `json:"domain" yaml:"domain"`
	Remote          XUIRemotePlan `json:"remote" yaml:"remote"`
	InstallRequired bool          `json:"install_required" yaml:"install_required"`
	Protocols       []Protocol    `json:"protocols" yaml:"protocols"`
	Conflicts       []XUIConflict `json:"conflicts,omitempty" yaml:"conflicts,omitempty"`
	Warnings        []string      `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	ComposePath     string        `json:"compose_path,omitempty" yaml:"compose_path,omitempty"`
	PlannedAt       time.Time     `json:"planned_at" yaml:"planned_at"`
}

type XUIRemotePlan struct {
	SSHHost       string `json:"ssh_host" yaml:"ssh_host"`
	SSHUser       string `json:"ssh_user" yaml:"ssh_user"`
	SSHPort       int    `json:"ssh_port" yaml:"ssh_port"`
	ContainerName string `json:"container_name,omitempty" yaml:"container_name,omitempty"`
	PanelPort     int    `json:"panel_port" yaml:"panel_port"`
	WebBasePath   string `json:"web_base_path,omitempty" yaml:"web_base_path,omitempty"`
}

type XUIConflict struct {
	Kind   string `json:"kind" yaml:"kind"`
	Name   string `json:"name" yaml:"name"`
	Detail string `json:"detail" yaml:"detail"`
	Action string `json:"action" yaml:"action"`
}

type XUIState struct {
	Domain        string            `json:"domain"`
	RemoteHost    string            `json:"remote_host"`
	ContainerName string            `json:"container_name,omitempty"`
	Installed     bool              `json:"installed"`
	AppliedAt     time.Time         `json:"applied_at"`
	Inbounds      []XUIInboundState `json:"inbounds"`
	Outbounds     []string          `json:"outbounds"`
	Warnings      []string          `json:"warnings,omitempty"`
}

type XUIInboundState struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
}

type ClientLinks struct {
	Clients []ClientLink `json:"clients" yaml:"clients"`
}

type ClientLink struct {
	Name     string `json:"name" yaml:"name"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Hostname string `json:"hostname" yaml:"hostname"`
	Link     string `json:"link" yaml:"link"`
}

type InactiveZoneError struct {
	Zone Zone
}

func (e InactiveZoneError) Error() string {
	return "cloudflare zone is not active"
}
