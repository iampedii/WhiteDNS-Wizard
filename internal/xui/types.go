package xui

import (
	"time"

	"github.com/whitedns/wdns-wizard/pkg/types"
)

type Input struct {
	Domain         string
	Root           string
	SSH            SSHConfig
	Panel          PanelCredentials
	ConfirmReplace bool
	ACMEEmail      string
	Progress       func(string)
}

type PanelCredentials struct {
	Username    string
	Password    string
	WebBasePath string
}

type Result struct {
	Plan       types.XUIPlan
	State      types.XUIState
	Links      types.ClientLinks
	ProjectDir string
	PublicCert string
	PublicKey  string
	LogPath    string
}

type ProjectSummary struct {
	Domain      string
	ProjectDir  string
	VPSIP       string
	SSHHost     string
	SSHPort     int
	ZoneStatus  string
	LastApplied time.Time
}

type CurrentInfo struct {
	Summary         ProjectSummary
	Config          types.ProjectConfig
	CloudflareState types.CloudflareState
	XUIState        types.XUIState
	ProtocolPlan    types.ProtocolPlan
	ClientLinksPath string
}

type DashboardInfo struct {
	Domain        string
	Username      string
	Password      string
	WebBasePath   string
	URL           string
	TunnelCommand string
}

type InboundSummary struct {
	ID       int
	Enabled  bool
	Remark   string
	Protocol string
	Port     int
	Network  string
	Security string
	Clients  int
}

type OutboundSummary struct {
	Tag      string
	Protocol string
}

type ClientSummary struct {
	Inbound    string
	Email      string
	Enabled    bool
	Identifier string
	ExpiryTime int64
	TotalGB    int64
}

type DeleteResult struct {
	DeletedInbounds     int
	RemovedOutbounds    int
	RemovedManagedStack bool
	ProjectDir          string
	Warnings            []string
}

type DiagnosticCheck struct {
	Name   string
	Status string
	Detail string
}

type DiagnosticsResult struct {
	ProjectDir string
	Checks     []DiagnosticCheck
}

type RepairResult struct {
	ProjectDir       string
	LogPath          string
	ReplacedInbounds int
	AddedInbounds    int
	UpdatedOutbounds bool
	Warnings         []string
}

type BackupResult struct {
	ProjectDir     string
	BackupDir      string
	RemoteArchive  string
	LocalBackupDir string
	Warnings       []string
}

type RestoreResult struct {
	ProjectDir     string
	BackupDir      string
	RestoredRemote bool
	RestoredLocal  bool
	Warnings       []string
}

type SupportBundleResult struct {
	ProjectDir string
	BundleDir  string
	Files      []string
	Warnings   []string
}

type RemoteInfo struct {
	DockerInstalled        bool
	DockerComposeInstalled bool
	ExistingDocker3XUI     bool
	ManagedDocker3XUI      bool
	ExistingNonDockerXUI   bool
	ContainerName          string
	Image                  string
	Warnings               []string
}

type Inbound struct {
	ID             int            `json:"id,omitempty"`
	Up             int64          `json:"up"`
	Down           int64          `json:"down"`
	Total          int64          `json:"total"`
	Remark         string         `json:"remark"`
	Enable         bool           `json:"enable"`
	ExpiryTime     int64          `json:"expiryTime"`
	TrafficReset   string         `json:"trafficReset"`
	Listen         string         `json:"listen"`
	Port           int            `json:"port"`
	Protocol       string         `json:"protocol"`
	Settings       map[string]any `json:"settings"`
	StreamSettings map[string]any `json:"streamSettings"`
	Tag            string         `json:"tag"`
	Sniffing       map[string]any `json:"sniffing"`
}

type ConflictError struct {
	Conflicts []types.XUIConflict
	Warnings  []string
}

func (e ConflictError) Error() string {
	return "3x-ui conflicts require confirmation before replacement"
}
