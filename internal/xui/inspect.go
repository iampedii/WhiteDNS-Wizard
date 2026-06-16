package xui

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	posixpath "path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/whitedns/wdns-wizard/internal/output"
	"github.com/whitedns/wdns-wizard/internal/planner"
	"github.com/whitedns/wdns-wizard/internal/secrets"
	"github.com/whitedns/wdns-wizard/pkg/types"
	"gopkg.in/yaml.v3"
)

func ProjectSummaries(root string) ([]ProjectSummary, error) {
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = output.DefaultRoot()
		if err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read project root: %w", err)
	}
	var summaries []ProjectSummary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domain := entry.Name()
		paths := output.Paths(root, domain)
		if _, err := os.Stat(paths.Config); err != nil {
			continue
		}
		summary, err := projectSummary(paths, domain)
		if err != nil {
			continue
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].LastApplied.Equal(summaries[j].LastApplied) {
			return summaries[i].Domain < summaries[j].Domain
		}
		return summaries[i].LastApplied.After(summaries[j].LastApplied)
	})
	return summaries, nil
}

func LoadCurrentInfo(root, domain string) (CurrentInfo, error) {
	normalized, err := planner.NormalizeDomain(domain)
	if err != nil {
		return CurrentInfo{}, err
	}
	if strings.TrimSpace(root) == "" {
		root, err = output.DefaultRoot()
		if err != nil {
			return CurrentInfo{}, err
		}
	}
	paths := output.Paths(root, normalized)
	config, err := readYAMLFile[types.ProjectConfig](paths.Config)
	if err != nil {
		return CurrentInfo{}, err
	}
	cfState, _ := readJSONFile[types.CloudflareState](paths.CloudflareState)
	xuiState, _ := readJSONFile[types.XUIState](paths.XUIState)
	protocolPlan, _ := readYAMLFile[types.ProtocolPlan](paths.ProtocolPlan)
	summary, err := projectSummary(paths, normalized)
	if err != nil {
		return CurrentInfo{}, err
	}
	summary.VPSIP = firstNonEmpty(summary.VPSIP, config.VPSIP)
	return CurrentInfo{
		Summary:         summary,
		Config:          config,
		CloudflareState: cfState,
		XUIState:        xuiState,
		ProtocolPlan:    protocolPlan,
		ClientLinksPath: paths.ClientLinksText,
	}, nil
}

func (p Provisioner) DashboardInfo(domain, root string) (DashboardInfo, error) {
	project, err := loadProject(root, domain)
	if err != nil {
		return DashboardInfo{}, err
	}
	info, err := LoadCurrentInfo(project.Root, project.Domain)
	if err != nil {
		return DashboardInfo{}, err
	}
	panel := panelFromInputOrSecrets(PanelCredentials{}, project.Secrets)
	remoteHost := firstNonEmpty(info.XUIState.RemoteHost, info.Summary.SSHHost, info.Config.VPSIP)
	remoteUser := "root"
	if remoteHost == "" {
		remoteHost = "<ssh-host>"
	}
	basePath := normalizeBasePath(panel.WebBasePath)
	return DashboardInfo{
		Domain:        project.Domain,
		Username:      panel.Username,
		Password:      panel.Password,
		WebBasePath:   basePath,
		URL:           "http://panel." + project.Domain + ":2053" + strings.TrimRight(basePath, "/") + "/",
		TunnelCommand: fmt.Sprintf("ssh -L 127.0.0.1:2053:127.0.0.1:2053 %s@%s", remoteUser, remoteHost),
	}, nil
}

func (p Provisioner) ListInbounds(ctx context.Context, input Input) ([]InboundSummary, error) {
	_, remote, tunnel, api, err := p.openPanel(ctx, input)
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	defer tunnel.Close()
	inbounds, err := api.ListInbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("list 3x-ui inbounds: %w", err)
	}
	var result []InboundSummary
	for _, inbound := range inbounds {
		result = append(result, summarizeInbound(inbound))
	}
	return result, nil
}

func (p Provisioner) ListOutbounds(ctx context.Context, input Input) ([]OutboundSummary, error) {
	_, remote, tunnel, api, err := p.openPanel(ctx, input)
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	defer tunnel.Close()
	config, _, err := api.GetXrayConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("read xray config: %w", err)
	}
	var result []OutboundSummary
	for _, outbound := range outbounds(config) {
		result = append(result, OutboundSummary{
			Tag:      fmt.Sprint(outbound["tag"]),
			Protocol: fmt.Sprint(outbound["protocol"]),
		})
	}
	return result, nil
}

func (p Provisioner) ListClients(ctx context.Context, input Input, limit int) ([]ClientSummary, error) {
	_, remote, tunnel, api, err := p.openPanel(ctx, input)
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	defer tunnel.Close()
	inbounds, err := api.ListInbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("list 3x-ui clients: %w", err)
	}
	if limit <= 0 {
		limit = 10
	}
	var result []ClientSummary
	for _, inbound := range inbounds {
		for _, client := range clientsFromSettings(inbound.Settings) {
			if len(result) >= limit {
				return result, nil
			}
			result = append(result, summarizeClient(inbound.Remark, client))
		}
	}
	return result, nil
}

func (p Provisioner) ResetManaged(ctx context.Context, input Input) (Result, error) {
	input.ConfirmReplace = true
	return p.Apply(ctx, input)
}

func (p Provisioner) DeleteManaged(ctx context.Context, input Input) (DeleteResult, error) {
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return DeleteResult{}, err
	}
	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		return DeleteResult{}, err
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		return DeleteResult{}, err
	}
	defer remote.Close()
	info, err := DetectRemote(ctx, remote)
	if err != nil {
		return DeleteResult{}, err
	}
	result := DeleteResult{ProjectDir: project.Paths.ProjectDir}
	if err := p.deleteManagedPanelEntries(ctx, input, project, remote, &result); err != nil {
		result.Warnings = append(result.Warnings, "Could not remove 3x-ui panel entries before stack removal: "+err.Error())
	}
	if info.ManagedDocker3XUI {
		if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres down --rmi all --volumes --remove-orphans"); err != nil {
			result.Warnings = append(result.Warnings, "Could not stop managed Docker stack and remove images: "+err.Error())
		} else {
			result.RemovedManagedStack = true
			result.RemovedDockerImages = true
		}
		if _, err := remote.Run(ctx, "docker builder prune -af"); err != nil {
			result.Warnings = append(result.Warnings, "Could not prune Docker build cache: "+err.Error())
		} else {
			result.PrunedBuildCache = true
		}
		if _, err := remote.Run(ctx, "rm -rf "+shQuote(RemoteBaseDir)); err != nil {
			result.Warnings = append(result.Warnings, "Could not remove managed files: "+err.Error())
		}
		if _, err := remote.Run(ctx, "if [ -d "+shQuote(OldRemoteBaseDir)+" ]; then rm -rf "+shQuote(OldRemoteBaseDir)+"; fi"); err != nil {
			result.Warnings = append(result.Warnings, "Could not remove legacy managed files: "+err.Error())
		}
	}
	return result, nil
}

func (p Provisioner) Diagnostics(ctx context.Context, input Input) (DiagnosticsResult, error) {
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return DiagnosticsResult{}, err
	}
	result := DiagnosticsResult{ProjectDir: project.Paths.ProjectDir}
	addCheck := func(name, status, detail string) {
		result.Checks = append(result.Checks, DiagnosticCheck{Name: name, Status: status, Detail: detail})
	}

	info, err := LoadCurrentInfo(project.Root, project.Domain)
	if err != nil {
		addCheck("local project", "FAIL", err.Error())
	} else {
		addCheck("local project", "PASS", info.Summary.ProjectDir)
		addCheck("cloudflare zone", statusFor(info.CloudflareState.Zone.Status == "active"), fmt.Sprintf("%s (%s)", info.CloudflareState.Zone.Name, info.CloudflareState.Zone.Status))
		addCheck("client links", statusFor(fileExists(info.ClientLinksPath)), info.ClientLinksPath)
		addRealitySNISecretChecks(addCheck, project.Secrets)
		addHy2DNSCheck(addCheck, project.Domain, info.Config.VPSIP)
		addHy2CloudflareCheck(addCheck, info)
		addShadowsocksDNSCheck(addCheck, project.Domain, info.Config.VPSIP)
		addShadowsocksCloudflareCheck(addCheck, info)
		addTorDNSChecks(addCheck, project.Domain, info.Config.VPSIP)
	}
	addCertCheck := func(name, path string) {
		expiry, err := certificateExpiry(path)
		if err != nil {
			addCheck(name, "FAIL", err.Error())
			return
		}
		status := "PASS"
		if time.Until(expiry) < 30*24*time.Hour {
			status = "WARN"
		}
		addCheck(name, status, "expires "+expiry.Format(time.RFC3339))
	}
	addCertCheck("origin certificate", project.Paths.OriginCert)
	addCertCheck("public certificate", project.Paths.PublicCert)

	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		addCheck("ssh", "FAIL", err.Error())
		return result, nil
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		addCheck("ssh", "FAIL", err.Error())
		return result, nil
	}
	defer remote.Close()
	addCheck("ssh", "PASS", input.SSH.User+"@"+input.SSH.Host)

	remoteInfo, err := DetectRemote(ctx, remote)
	if err != nil {
		addCheck("remote inspection", "FAIL", err.Error())
	} else {
		addCheck("docker", statusFor(remoteInfo.DockerInstalled), fmt.Sprintf("compose=%t managed=%t container=%s", remoteInfo.DockerComposeInstalled, remoteInfo.ManagedDocker3XUI, firstNonEmpty(remoteInfo.ContainerName, "unknown")))
		for _, warning := range remoteInfo.Warnings {
			addCheck("remote warning", "WARN", warning)
		}
	}
	addRemoteCheck(ctx, remote, addCheck, "docker containers", "docker ps --format '{{.Names}} {{.Status}} {{.Ports}}'")
	addDockerUDP443Check(ctx, remote, addCheck)
	addDockerPortBindingCheck(ctx, remote, addCheck, "docker 8388/tcp", "8388/tcp", "8388")
	addDockerPortBindingCheck(ctx, remote, addCheck, "docker 8388/udp", "8388/udp", "8388")
	addTorContainerCheck(ctx, remote, addCheck)
	addTorPortPrivateCheck(ctx, remote, addCheck)
	addRemoteCheck(ctx, remote, addCheck, "firewall", "sh -lc 'if command -v ufw >/dev/null 2>&1; then ufw status; elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state && firewall-cmd --list-ports; else echo no ufw/firewalld detected; fi'")
	addRemoteCheck(ctx, remote, addCheck, "listening ports", "sh -lc 'if command -v ss >/dev/null 2>&1; then ss -lntup; else netstat -tulpen 2>/dev/null || true; fi'")

	for _, port := range []int{2053, 443, 8443, 2083, 2087, 8388, 2097, 2098, 2100, 2101, 8390} {
		host := portHost(project.Domain, port)
		addCheck("tcp "+host, tcpStatus(host, port), net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	}
	addCheck("udp hy2."+project.Domain+":443", "WARN", "UDP reachability is not tested locally; verify with a Hysteria2 client.")
	addCheck("tor udp profiles", "WARN", "Tor is TCP-only; UDP destination traffic from Tor Hysteria2/Shadowsocks profiles may fail rather than route direct.")

	panel := panelFromInputOrSecrets(input.Panel, project.Secrets)
	tunnel, api, err := p.panelClientForRemote(ctx, input, project, remote, panel)
	if err != nil {
		addCheck("3x-ui panel login", "FAIL", err.Error())
		return result, nil
	}
	defer tunnel.Close()
	addCheck("3x-ui panel login", "PASS", panel.WebBasePath)
	if config, _, err := api.GetXrayConfig(ctx); err != nil {
		addCheck("xray config", "FAIL", err.Error())
	} else {
		addCheck("xray config", "PASS", "3x-ui API returned Xray config")
		addTorXrayConfigChecks(addCheck, config)
	}
	if inbounds, err := api.ListInbounds(ctx); err != nil {
		addCheck("inbounds", "FAIL", err.Error())
	} else {
		addCheck("inbounds", "PASS", fmt.Sprintf("%d total inbounds", len(inbounds)))
		links, _ := readYAMLFile[types.ClientLinks](project.Paths.ClientLinks)
		addRealityConfigChecks(addCheck, inbounds, links, project.Secrets)
		addHysteria2ConfigChecks(addCheck, inbounds)
		addShadowsocksConfigChecks(addCheck, inbounds)
	}
	return result, nil
}

func (p Provisioner) RepairManaged(ctx context.Context, input Input) (RepairResult, error) {
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return RepairResult{}, err
	}
	progress := newProgressRecorder(input.Progress)
	progress.SetPath(project.Paths.XUILog)
	progress.Log("Preparing repair and validating saved Reality SNI values.")
	if changed, err := project.ensureXUISecrets(input.Panel); err != nil {
		return RepairResult{}, err
	} else if changed {
		if err := project.saveSecrets(); err != nil {
			return RepairResult{}, err
		}
	}
	if changed, err := project.ensureGeneratedPanelCredentials(); err != nil {
		return RepairResult{}, err
	} else if changed {
		if err := project.saveSecrets(); err != nil {
			return RepairResult{}, err
		}
	}
	if changed := project.ensureValidatedRealitySNIs(ctx, p.RealitySNIValidator, progress); changed {
		if err := project.saveSecrets(); err != nil {
			return RepairResult{}, err
		}
	}
	bundle, err := BuildProtocolBundle(project.Domain, project.Secrets)
	if err != nil {
		return RepairResult{}, err
	}
	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		return RepairResult{}, err
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		return RepairResult{}, err
	}
	defer remote.Close()

	progress.Log("Repairing managed Docker 3x-ui stack without Cloudflare changes.")
	if err := EnsureManagedDocker3XUI(ctx, remote, project.Secrets); err != nil {
		return RepairResult{}, err
	}
	warnings := ApplyFirewall(ctx, remote)
	for _, warning := range warnings {
		progress.Log("Warning: " + warning)
	}
	progress.Log("Uploading existing local certificates.")
	if err := uploadCertificates(ctx, remote, project.Paths); err != nil {
		return RepairResult{}, fmt.Errorf("upload existing certificates for repair: %w", err)
	}

	panel := panelFromInputOrSecrets(input.Panel, project.Secrets)
	tunnel, api, err := p.panelClientForRemote(ctx, input, project, remote, panel)
	if err != nil {
		return RepairResult{}, err
	}
	defer tunnel.Close()
	inbounds, err := api.ListInbounds(ctx)
	if err != nil {
		return RepairResult{}, fmt.Errorf("list 3x-ui inbounds: %w", err)
	}
	xrayConfig, outboundTestURL, err := api.GetXrayConfig(ctx)
	if err != nil {
		return RepairResult{}, fmt.Errorf("read xray outbound config: %w", err)
	}

	result := RepairResult{ProjectDir: project.Paths.ProjectDir, LogPath: project.Paths.XUILog, Warnings: warnings}
	for _, id := range matchingInboundIDs(inbounds, bundle.Inbounds) {
		if err := api.DeleteInbound(ctx, id); err != nil {
			return RepairResult{}, fmt.Errorf("delete managed inbound %d: %w", id, err)
		}
		result.ReplacedInbounds++
	}
	xrayConfig = EnsureOutbounds(xrayConfig)
	if err := api.UpdateXrayConfig(ctx, xrayConfig, outboundTestURL); err != nil {
		return RepairResult{}, fmt.Errorf("update xray outbounds: %w", err)
	}
	result.UpdatedOutbounds = true
	var inboundStates []types.XUIInboundState
	for _, inbound := range bundle.Inbounds {
		if _, err := api.AddInbound(ctx, inbound); err != nil {
			return RepairResult{}, fmt.Errorf("add managed inbound %s: %w", inbound.Tag, err)
		}
		result.AddedInbounds++
		inboundStates = append(inboundStates, types.XUIInboundState{
			Tag:      inbound.Tag,
			Protocol: inbound.Protocol,
			Hostname: hostnameForTag(bundle.Plan.Protocols, inbound.Tag),
			Port:     inbound.Port,
			Network:  networkForTag(bundle.Plan.Protocols, inbound.Tag),
		})
	}
	_ = api.RestartXray(ctx)
	progress.Log("Repair complete.")
	state := types.XUIState{
		Domain:        project.Domain,
		RemoteHost:    input.SSH.Host,
		ContainerName: "3xui_app",
		Installed:     true,
		AppliedAt:     time.Now().UTC(),
		Inbounds:      inboundStates,
		Outbounds:     managedOutboundTags(),
		Warnings:      warnings,
	}
	publicCert, _ := os.ReadFile(project.Paths.PublicCert)
	publicKey, _ := os.ReadFile(project.Paths.PublicKey)
	plan := buildPlan(project.Domain, input, RemoteInfo{ExistingDocker3XUI: true, ManagedDocker3XUI: true, ContainerName: "3xui_app"}, bundle, nil)
	plan.Warnings = append(plan.Warnings, warnings...)
	if err := output.WriteXUI(project.Paths, plan, state, bundle.Links, string(publicCert), string(publicKey), progress.Body()+"\n"+renderLog(plan, state)); err != nil {
		return RepairResult{}, err
	}
	return result, nil
}

func (p Provisioner) BackupManaged(ctx context.Context, input Input) (BackupResult, error) {
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return BackupResult{}, err
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	backupDir := filepath.Join(project.Paths.ProjectDir, "backups", "backup-"+stamp)
	localDir := filepath.Join(backupDir, "local-project")
	if err := copyDir(project.Paths.ProjectDir, localDir, "backups", "support-bundles"); err != nil {
		return BackupResult{}, fmt.Errorf("backup local project files: %w", err)
	}
	result := BackupResult{ProjectDir: project.Paths.ProjectDir, BackupDir: backupDir, LocalBackupDir: localDir}

	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		result.Warnings = append(result.Warnings, "remote backup skipped: "+err.Error())
		return result, nil
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		result.Warnings = append(result.Warnings, "remote backup skipped: "+err.Error())
		return result, nil
	}
	defer remote.Close()
	out, err := remote.Run(ctx, "sh -lc "+shQuote(remoteBackupScript()))
	if err != nil {
		result.Warnings = append(result.Warnings, "remote backup failed: "+err.Error())
		return result, nil
	}
	encoded := strings.Join(strings.Fields(out), "")
	if encoded == "" {
		result.Warnings = append(result.Warnings, "remote managed directory was not found")
		return result, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return BackupResult{}, fmt.Errorf("decode remote backup archive: %w", err)
	}
	result.RemoteArchive = filepath.Join(backupDir, "remote-managed.tar.gz")
	if err := os.WriteFile(result.RemoteArchive, data, 0o600); err != nil {
		return BackupResult{}, fmt.Errorf("write remote backup archive: %w", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "manifest.txt"), []byte(RenderBackupResult(result)+"\n"), 0o644); err != nil {
		return BackupResult{}, fmt.Errorf("write backup manifest: %w", err)
	}
	return result, nil
}

func (p Provisioner) RestoreLatestBackup(ctx context.Context, input Input) (RestoreResult, error) {
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return RestoreResult{}, err
	}
	backupDir, err := latestBackupDir(project.Paths.ProjectDir)
	if err != nil {
		return RestoreResult{}, err
	}
	result := RestoreResult{ProjectDir: project.Paths.ProjectDir, BackupDir: backupDir}

	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		return RestoreResult{}, err
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		return RestoreResult{}, err
	}
	defer remote.Close()
	archive := filepath.Join(backupDir, "remote-managed.tar.gz")
	if fileExists(archive) {
		data, err := os.ReadFile(archive)
		if err != nil {
			return RestoreResult{}, fmt.Errorf("read remote backup archive: %w", err)
		}
		remoteTmp := "/tmp/wdns-wizard-restore-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
		if err := remote.Upload(ctx, remoteTmp, data, 0o600); err != nil {
			return RestoreResult{}, err
		}
		if _, err := remote.Run(ctx, "sh -lc "+shQuote(remoteRestoreScript(remoteTmp))); err != nil {
			return RestoreResult{}, fmt.Errorf("restore remote managed stack: %w", err)
		}
		result.RestoredRemote = true
	} else {
		result.Warnings = append(result.Warnings, "remote archive not found in latest backup")
	}
	localDir := filepath.Join(backupDir, "local-project")
	if fileExists(localDir) {
		if err := copyDir(localDir, project.Paths.ProjectDir, "backups", "support-bundles"); err != nil {
			return RestoreResult{}, fmt.Errorf("restore local project files: %w", err)
		}
		result.RestoredLocal = true
	} else {
		result.Warnings = append(result.Warnings, "local project backup directory not found")
	}
	return result, nil
}

func (p Provisioner) SupportBundle(ctx context.Context, input Input) (SupportBundleResult, error) {
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return SupportBundleResult{}, err
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	bundleDir := filepath.Join(project.Paths.ProjectDir, "support-bundles", "support-"+stamp)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		return SupportBundleResult{}, fmt.Errorf("create support bundle: %w", err)
	}
	result := SupportBundleResult{ProjectDir: project.Paths.ProjectDir, BundleDir: bundleDir}
	writeSupport := func(name, body string) {
		path := filepath.Join(bundleDir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			result.Warnings = append(result.Warnings, "could not write "+name+": "+err.Error())
			return
		}
		result.Files = append(result.Files, path)
	}
	if info, err := LoadCurrentInfo(project.Root, project.Domain); err == nil {
		writeSupport("current-info.txt", RenderCurrentInfo(info)+"\n")
	} else {
		result.Warnings = append(result.Warnings, "current info failed: "+err.Error())
	}
	if diagnostics, err := p.Diagnostics(ctx, input); err == nil {
		writeSupport("diagnostics.txt", RenderDiagnostics(diagnostics)+"\n")
	} else {
		result.Warnings = append(result.Warnings, "diagnostics failed: "+err.Error())
	}
	for _, file := range []string{project.Paths.Config, project.Paths.CloudflareState, project.Paths.XUIState, project.Paths.DNSPlan, project.Paths.ProtocolPlan, project.Paths.XUIPlan} {
		if data, err := os.ReadFile(file); err == nil {
			writeSupport(filepath.Base(file), string(data))
		}
	}
	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		result.Warnings = append(result.Warnings, "remote support data skipped: "+err.Error())
		return result, nil
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		result.Warnings = append(result.Warnings, "remote support data skipped: "+err.Error())
		return result, nil
	}
	defer remote.Close()
	for _, item := range []struct {
		name string
		cmd  string
	}{
		{"docker-ps.txt", "docker ps --format '{{.Names}} {{.Image}} {{.Status}} {{.Ports}}' 2>&1 || true"},
		{"docker-logs-3xui-app.txt", "docker logs --tail 160 3xui_app 2>&1 || true"},
		{"docker-logs-3xui-postgres.txt", "docker logs --tail 120 3xui_postgres 2>&1 || true"},
		{"docker-logs-3xui-tor.txt", "docker logs --tail 120 3xui_tor 2>&1 || true"},
		{"xray-reality-config.txt", `docker exec 3xui_app sh -lc 'grep -n -A80 -B10 "wdns-reality-tcp-vision\|wdns-tor-reality-tcp-vision\|wdns-reality-xhttp\|wdns-tor-reality-xhttp" /app/bin/config.json 2>/dev/null || grep -n -A80 -B10 "wdns-reality-tcp-vision\|wdns-tor-reality-tcp-vision\|wdns-reality-xhttp\|wdns-tor-reality-xhttp" bin/config.json 2>/dev/null || true'`},
		{"firewall.txt", "sh -lc 'if command -v ufw >/dev/null 2>&1; then ufw status verbose; elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state && firewall-cmd --list-all; else echo no ufw/firewalld detected; fi'"},
		{"ports.txt", "sh -lc 'if command -v ss >/dev/null 2>&1; then ss -lntup; else netstat -tulpen 2>/dev/null || true; fi'"},
	} {
		out, err := remote.Run(ctx, item.cmd)
		if err != nil {
			out = err.Error()
		}
		writeSupport(item.name, out)
	}
	return result, nil
}

func ReuseManagedSecrets(root, fromDomain, toDomain string) error {
	from, err := loadProject(root, fromDomain)
	if err != nil {
		return err
	}
	to, err := loadProject(root, toDomain)
	if err != nil {
		return err
	}
	for _, key := range []string{
		"vless_uuid",
		"vless_8443_uuid",
		"direct_vless_uuid",
		"reality_vless_uuid",
		"reality_private_key",
		"reality_public_key",
		"reality_short_id",
		"reality_mldsa65_seed",
		"reality_mlkem_decryption",
		"reality_mlkem_encryption",
		"reality_sni",
		"trojan_password",
		"hysteria2_password",
		"hysteria2_obfs_password",
		"shadowsocks_server_password",
		"shadowsocks_client_password",
		"tor_vless_uuid",
		"tor_vless_8443_uuid",
		"tor_direct_vless_uuid",
		"tor_reality_vless_uuid",
		"tor_reality_private_key",
		"tor_reality_public_key",
		"tor_reality_short_id",
		"tor_reality_mldsa65_seed",
		"tor_reality_mlkem_decryption",
		"tor_reality_mlkem_encryption",
		"tor_reality_sni",
		"tor_hysteria2_password",
		"tor_hysteria2_obfs_password",
		"tor_shadowsocks_server_password",
		"tor_shadowsocks_client_password",
		"vless_ws_path",
		"trojan_ws_path",
		"postgres_password",
		"panel_username",
		"panel_password",
		"panel_base_path",
	} {
		if strings.TrimSpace(from.Secrets[key]) != "" {
			to.Secrets[key] = from.Secrets[key]
		}
	}
	if err := to.saveSecrets(); err != nil {
		return err
	}
	generated := generatedFromValues(to.Secrets)
	plan := planner.GenerateProtocolPlan(to.Domain, generated)
	data, err := yaml.Marshal(plan)
	if err != nil {
		return fmt.Errorf("marshal protocol plan: %w", err)
	}
	if err := os.WriteFile(to.Paths.ProtocolPlan, data, 0o644); err != nil {
		return fmt.Errorf("write protocol plan: %w", err)
	}
	return nil
}

func RenderCurrentInfo(info CurrentInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\n", info.Summary.Domain)
	fmt.Fprintf(&b, "Directory: %s\n", info.Summary.ProjectDir)
	fmt.Fprintf(&b, "VPS IP: %s\n", info.Config.VPSIP)
	fmt.Fprintf(&b, "Zone: %s (%s)\n", info.CloudflareState.Zone.Name, info.CloudflareState.Zone.Status)
	if info.XUIState.RemoteHost != "" {
		fmt.Fprintf(&b, "Remote: %s (%s)\n", info.XUIState.RemoteHost, info.XUIState.ContainerName)
	}
	if !info.XUIState.AppliedAt.IsZero() {
		fmt.Fprintf(&b, "Last x-ui apply: %s\n", info.XUIState.AppliedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "Client links: %s\n\n", info.ClientLinksPath)
	b.WriteString("DNS records:\n")
	for _, result := range info.CloudflareState.DNSResults {
		fmt.Fprintf(&b, "- %-10s %s\n", result.Status, result.Record.Name)
	}
	b.WriteString("\nProtocols:\n")
	for _, proto := range info.ProtocolPlan.Protocols {
		if proto.Enabled {
			fmt.Fprintf(&b, "- %-24s %s:%d/%s %s\n", DisplayNameForTag(proto.Tag), proto.Hostname, proto.Port, firstNonEmpty(proto.Network, "tcp"), proto.Transport)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderDashboardInfo(info DashboardInfo) string {
	return fmt.Sprintf("Panel URL: %s\nUsername: %s\nPassword: %s\nBase path: %s\nPrivate tunnel fallback: %s",
		info.URL, info.Username, info.Password, info.WebBasePath, info.TunnelCommand)
}

func RenderInbounds(inbounds []InboundSummary) string {
	if len(inbounds) == 0 {
		return "No inbounds found."
	}
	var b strings.Builder
	for _, item := range inbounds {
		state := "disabled"
		if item.Enabled {
			state = "enabled"
		}
		fmt.Fprintf(&b, "%-4d %-8s %-28s %-10s %5d %-8s %-8s clients=%d\n", item.ID, state, DisplayNameForTag(item.Remark), item.Protocol, item.Port, item.Network, item.Security, item.Clients)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderOutbounds(outbounds []OutboundSummary) string {
	if len(outbounds) == 0 {
		return "No outbounds found."
	}
	var b strings.Builder
	for _, item := range outbounds {
		fmt.Fprintf(&b, "%-28s %s\n", DisplayNameForTag(item.Tag), item.Protocol)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderClients(clients []ClientSummary) string {
	if len(clients) == 0 {
		return "No clients found."
	}
	var b strings.Builder
	for _, client := range clients {
		state := "disabled"
		if client.Enabled {
			state = "enabled"
		}
		fmt.Fprintf(&b, "%-28s %-28s %-8s %-36s expiry=%d totalGB=%d\n", DisplayNameForTag(client.Inbound), client.Email, state, client.Identifier, client.ExpiryTime, client.TotalGB)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderDeleteResult(result DeleteResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Deleted inbounds: %d\n", result.DeletedInbounds)
	fmt.Fprintf(&b, "Removed outbounds: %d\n", result.RemovedOutbounds)
	fmt.Fprintf(&b, "Removed managed stack: %t\n", result.RemovedManagedStack)
	fmt.Fprintf(&b, "Removed Docker images: %t\n", result.RemovedDockerImages)
	fmt.Fprintf(&b, "Pruned Docker build cache: %t\n", result.PrunedBuildCache)
	fmt.Fprintf(&b, "Local project kept: %s\n", result.ProjectDir)
	for _, warning := range result.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", warning)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderDiagnostics(result DiagnosticsResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\n\n", result.ProjectDir)
	for _, check := range result.Checks {
		fmt.Fprintf(&b, "%-5s %-24s %s\n", check.Status, check.Name, check.Detail)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderRepairResult(result RepairResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\n", result.ProjectDir)
	fmt.Fprintf(&b, "Replaced inbounds: %d\n", result.ReplacedInbounds)
	fmt.Fprintf(&b, "Added inbounds: %d\n", result.AddedInbounds)
	fmt.Fprintf(&b, "Updated outbounds: %t\n", result.UpdatedOutbounds)
	if result.LogPath != "" {
		fmt.Fprintf(&b, "Log file: %s\n", result.LogPath)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", warning)
	}
	return strings.TrimRight(b.String(), "\n")
}

func remoteBackupScript() string {
	parent := posixpath.Dir(RemoteBaseDir)
	name := posixpath.Base(RemoteBaseDir)
	return "if [ -d " + shQuote(RemoteBaseDir) + " ]; then tar -C " + shQuote(parent) + " -czf - " + shQuote(name) + " | base64; fi"
}

func remoteRestoreScript(remoteTmp string) string {
	parent := posixpath.Dir(RemoteBaseDir)
	return "if [ -d " + shQuote(RemoteBaseDir) + " ]; then cd " + shQuote(RemoteBaseDir) + " && docker compose --profile postgres down || true; fi; " +
		"mkdir -p " + shQuote(parent) + "; " +
		"if [ -d " + shQuote(RemoteBaseDir) + " ]; then mv " + shQuote(RemoteBaseDir) + " " + shQuote(RemoteBaseDir) + ".pre-restore.$(date -u +%Y%m%d-%H%M%S); fi; " +
		"tar -C " + shQuote(parent) + " -xzf " + shQuote(remoteTmp) + "; " +
		"cd " + shQuote(RemoteBaseDir) + " && docker compose --profile postgres up -d --force-recreate"
}

func RenderBackupResult(result BackupResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\n", result.ProjectDir)
	fmt.Fprintf(&b, "Backup directory: %s\n", result.BackupDir)
	fmt.Fprintf(&b, "Local project backup: %s\n", result.LocalBackupDir)
	if result.RemoteArchive != "" {
		fmt.Fprintf(&b, "Remote stack archive: %s\n", result.RemoteArchive)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", warning)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderRestoreResult(result RestoreResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\n", result.ProjectDir)
	fmt.Fprintf(&b, "Backup directory: %s\n", result.BackupDir)
	fmt.Fprintf(&b, "Restored remote stack: %t\n", result.RestoredRemote)
	fmt.Fprintf(&b, "Restored local project files: %t\n", result.RestoredLocal)
	for _, warning := range result.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", warning)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RenderSupportBundleResult(result SupportBundleResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\n", result.ProjectDir)
	fmt.Fprintf(&b, "Support bundle: %s\n\n", result.BundleDir)
	b.WriteString("Files:\n")
	for _, file := range result.Files {
		fmt.Fprintf(&b, "- %s\n", file)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", warning)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (p Provisioner) panelClientForRemote(ctx context.Context, input Input, project projectData, remote Remote, panel PanelCredentials) (Tunnel, *APIClient, error) {
	tunnel, err := remote.Tunnel(ctx, "127.0.0.1", PanelPort)
	if err != nil {
		return Tunnel{}, nil, err
	}
	apiFactory := p.APIClient
	if apiFactory == nil {
		apiFactory = NewAPIClient
	}
	api, err := apiFactory("http://"+tunnel.LocalAddr, panel.WebBasePath)
	if err != nil {
		_ = tunnel.Close()
		return Tunnel{}, nil, err
	}
	if err := retry(ctx, 10, time.Second, func() error {
		return api.Login(ctx, panel.Username, panel.Password)
	}); err != nil {
		_ = tunnel.Close()
		return Tunnel{}, nil, fmt.Errorf("login to 3x-ui panel: %w", err)
	}
	return tunnel, api, nil
}

func statusFor(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func addRemoteCheck(ctx context.Context, remote Remote, add func(string, string, string), name, command string) {
	out, err := remote.Run(ctx, command)
	if err != nil {
		add(name, "FAIL", err.Error())
		return
	}
	out = strings.TrimSpace(out)
	if out == "" {
		out = "ok"
	}
	add(name, "PASS", firstLine(out))
}

func addHy2DNSCheck(add func(string, string, string), domain, expectedIP string) {
	host := "hy2." + domain
	ips, err := net.LookupHost(host)
	if err != nil {
		add("dns "+host, "FAIL", err.Error())
		return
	}
	status := "PASS"
	detail := strings.Join(ips, ", ")
	if strings.TrimSpace(expectedIP) != "" && !stringSliceContains(ips, expectedIP) {
		status = "WARN"
		detail += "; expected VPS IP " + expectedIP
	}
	add("dns "+host, status, detail)
}

func addShadowsocksDNSCheck(add func(string, string, string), domain, expectedIP string) {
	host := "ss." + domain
	ips, err := net.LookupHost(host)
	if err != nil {
		add("dns "+host, "FAIL", err.Error())
		return
	}
	status := "PASS"
	detail := strings.Join(ips, ", ")
	if strings.TrimSpace(expectedIP) != "" && !stringSliceContains(ips, expectedIP) {
		status = "WARN"
		detail += "; expected VPS IP " + expectedIP
	}
	add("dns "+host, status, detail)
}

func addHy2CloudflareCheck(add func(string, string, string), info CurrentInfo) {
	host := "hy2." + info.Summary.Domain
	for _, result := range info.CloudflareState.DNSResults {
		if result.Record.Name == host {
			if result.Record.Proxied {
				add("hysteria2 cloudflare", "FAIL", host+" is proxied; Hysteria2 UDP requires DNS-only.")
				return
			}
			add("hysteria2 cloudflare", "PASS", host+" is DNS-only; keep Cloudflare proxy disabled for Hysteria2 UDP.")
			return
		}
	}
	add("hysteria2 cloudflare", "WARN", host+" must stay DNS-only; Cloudflare proxy cannot carry Hysteria2 UDP.")
}

func addShadowsocksCloudflareCheck(add func(string, string, string), info CurrentInfo) {
	host := "ss." + info.Summary.Domain
	for _, result := range info.CloudflareState.DNSResults {
		if result.Record.Name == host {
			if result.Record.Proxied {
				add("shadowsocks cloudflare", "FAIL", host+" is proxied; Shadowsocks requires DNS-only.")
				return
			}
			add("shadowsocks cloudflare", "PASS", host+" is DNS-only; keep Cloudflare proxy disabled for Shadowsocks.")
			return
		}
	}
	add("shadowsocks cloudflare", "WARN", host+" must stay DNS-only; Cloudflare proxy cannot carry Shadowsocks.")
}

func addTorDNSChecks(add func(string, string, string), domain, expectedIP string) {
	for _, host := range []string{
		"tor-vless-ws." + domain,
		"tor-vless-ws-8443." + domain,
		"tor-hy2." + domain,
		"tor-direct." + domain,
		"tor-reality." + domain,
		"tor-ss." + domain,
	} {
		ips, err := net.LookupHost(host)
		if err != nil {
			add("dns "+host, "FAIL", err.Error())
			continue
		}
		status := "PASS"
		detail := strings.Join(ips, ", ")
		if strings.TrimSpace(expectedIP) != "" && !stringSliceContains(ips, expectedIP) {
			status = "WARN"
			detail += "; expected VPS IP " + expectedIP
		}
		add("dns "+host, status, detail)
	}
}

func addDockerUDP443Check(ctx context.Context, remote Remote, add func(string, string, string)) {
	out, err := remote.Run(ctx, "sh -lc "+shQuote("docker inspect 3xui_app --format '{{json .HostConfig.PortBindings}}' 2>/dev/null || true"))
	if err != nil {
		add("docker 443/udp", "FAIL", err.Error())
		return
	}
	out = strings.TrimSpace(out)
	if strings.Contains(out, "443/udp") && strings.Contains(out, `"HostPort":"443"`) {
		add("docker 443/udp", "PASS", "3xui_app publishes 443/udp")
		return
	}
	if out == "" {
		out = "no Docker port binding output"
	}
	add("docker 443/udp", "FAIL", out)
}

func addTorContainerCheck(ctx context.Context, remote Remote, add func(string, string, string)) {
	out, err := remote.Run(ctx, "docker ps --format '{{.Names}} {{.Status}}' | grep '^3xui_tor ' || true")
	if err != nil {
		add("tor container", "FAIL", err.Error())
		return
	}
	out = strings.TrimSpace(out)
	if strings.Contains(out, "3xui_tor") && strings.Contains(strings.ToLower(out), "up") {
		add("tor container", "PASS", firstLine(out))
		return
	}
	if out == "" {
		out = "3xui_tor is not running"
	}
	add("tor container", "FAIL", out)
}

func addTorPortPrivateCheck(ctx context.Context, remote Remote, add func(string, string, string)) {
	out, err := remote.Run(ctx, "sh -lc "+shQuote("docker inspect 3xui_tor --format '{{json .HostConfig.PortBindings}}' 2>/dev/null || true"))
	if err != nil {
		add("tor 9050 private", "FAIL", err.Error())
		return
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "null" || out == "{}" {
		add("tor 9050 private", "PASS", "3xui_tor does not publish 9050")
		return
	}
	if strings.Contains(out, "9050") {
		add("tor 9050 private", "FAIL", "9050 appears to be publicly published: "+out)
		return
	}
	add("tor 9050 private", "PASS", out)
}

func addDockerPortBindingCheck(ctx context.Context, remote Remote, add func(string, string, string), name, portProto, hostPort string) {
	out, err := remote.Run(ctx, "sh -lc "+shQuote("docker inspect 3xui_app --format '{{json .HostConfig.PortBindings}}' 2>/dev/null || true"))
	if err != nil {
		add(name, "FAIL", err.Error())
		return
	}
	out = strings.TrimSpace(out)
	if strings.Contains(out, portProto) && strings.Contains(out, `"HostPort":"`+hostPort+`"`) {
		add(name, "PASS", "3xui_app publishes "+portProto)
		return
	}
	if out == "" {
		out = "no Docker port binding output"
	}
	add(name, "FAIL", out)
}

func addTorXrayConfigChecks(add func(string, string, string), config map[string]any) {
	if torOutboundPresent(config) {
		add("tor outbound", "PASS", "wdns-tor routes to tor:9050")
	} else {
		add("tor outbound", "FAIL", "expected wdns-tor SOCKS outbound to tor:9050")
	}
	missing := missingTorRoutingTags(config)
	if len(missing) == 0 {
		add("tor routing", "PASS", "all Tor inbounds route to wdns-tor")
	} else {
		add("tor routing", "FAIL", "missing inboundTag routes: "+strings.Join(missing, ", "))
	}
}

func addRealitySNISecretChecks(add func(string, string, string), values map[string]string) {
	for _, item := range []struct {
		name string
		key  string
	}{
		{name: "reality sni", key: "reality_sni"},
		{name: "tor reality sni", key: "tor_reality_sni"},
	} {
		sni := strings.TrimSpace(values[item.key])
		if sni == "" {
			add(item.name, "WARN", item.key+" is empty; apply will select a validated fallback")
			continue
		}
		add(item.name, "PASS", "selected "+sni)
	}
}

func addRealityConfigChecks(add func(string, string, string), inbounds []Inbound, links types.ClientLinks, values map[string]string) {
	for _, item := range []struct {
		name   string
		tag    string
		legacy string
		sniKey string
	}{
		{name: "reality config", tag: "wdns-reality-tcp-vision", legacy: "wdns-reality-xhttp", sniKey: "reality_sni"},
		{name: "tor reality config", tag: "wdns-tor-reality-tcp-vision", legacy: "wdns-tor-reality-xhttp", sniKey: "tor_reality_sni"},
	} {
		expected := strings.TrimSpace(values[item.sniKey])
		if expected == "" {
			add(item.name, "WARN", item.sniKey+" is empty")
			continue
		}
		inbound, ok := findInboundByTag(inbounds, item.tag)
		if !ok {
			if _, legacy := findInboundByTag(inbounds, item.legacy); legacy {
				add(item.name, "FAIL", "legacy Reality XHTTP inbound found; rerun apply to replace it with TCP Vision")
				continue
			}
			add(item.name, "FAIL", "managed inbound not found")
			continue
		}
		stream, _ := normalizedMap(inbound.StreamSettings)
		if stream["network"] == "tcp" && stream["security"] == "reality" {
			add(item.name+" transport", "PASS", "network=tcp security=reality")
		} else {
			add(item.name+" transport", "FAIL", fmt.Sprintf("expected network=tcp security=reality, got network=%v security=%v", stream["network"], stream["security"]))
		}
		if _, hasXHTTP := stream["xhttpSettings"]; hasXHTTP {
			add(item.name+" xhttp", "FAIL", "legacy xhttpSettings found; rerun apply to recreate the inbound")
		} else {
			add(item.name+" xhttp", "PASS", "no xhttpSettings present")
		}
		if realityInboundHasVisionFlow(inbound) {
			add(item.name+" flow", "PASS", "client flow="+realityVisionFlow)
		} else {
			add(item.name+" flow", "FAIL", "client flow is missing "+realityVisionFlow)
		}
		settings, _ := normalizedMap(stream["realitySettings"])
		target := strings.TrimSpace(fmt.Sprint(settings["target"]))
		serverNames := stringList(settings["serverNames"])
		if target == expected+":443" && stringSliceContains(serverNames, expected) {
			add(item.name, "PASS", "target and serverNames match "+expected)
		} else {
			add(item.name, "WARN", fmt.Sprintf("expected target %s:443 and serverNames [%s], got target %s and serverNames %v", expected, expected, target, serverNames))
		}
		if realityClientLinkMatches(links, item.tag, expected) {
			add(item.name+" link", "PASS", "client link uses sni="+expected)
		} else {
			add(item.name+" link", "WARN", "client link is missing or does not use sni="+expected)
		}
	}
}

func findInboundByTag(inbounds []Inbound, tag string) (Inbound, bool) {
	for _, inbound := range inbounds {
		if inbound.Tag == tag {
			return inbound, true
		}
	}
	return Inbound{}, false
}

func normalizedMap(value any) (map[string]any, bool) {
	data, _ := json.Marshal(value)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

func realityClientLinkMatches(links types.ClientLinks, tag, expectedSNI string) bool {
	remark := DisplayNameForTag(tag)
	for _, client := range links.Clients {
		if client.Name == remark &&
			strings.Contains(client.Link, "type=tcp") &&
			strings.Contains(client.Link, "flow="+realityVisionFlow) &&
			strings.Contains(client.Link, "security=reality") &&
			strings.Contains(client.Link, "sni="+expectedSNI) &&
			strings.Contains(client.Link, "spx=%2F") {
			return true
		}
	}
	return false
}

func realityInboundHasVisionFlow(inbound Inbound) bool {
	for _, client := range clientsFromSettings(inbound.Settings) {
		if fmt.Sprint(client["flow"]) == realityVisionFlow {
			return true
		}
	}
	return false
}

func addHysteria2ConfigChecks(add func(string, string, string), inbounds []Inbound) {
	inbound, ok := hysteria2Inbound(inbounds)
	if !ok {
		add("hysteria2 config", "FAIL", "managed Hysteria2 inbound not found")
		return
	}
	if hasArrayKey(inbound.Settings, "clients") {
		add("hysteria2 clients", "PASS", "settings.clients is used for 3x-ui client management")
	} else if hasArrayKey(inbound.Settings, "users") {
		add("hysteria2 clients", "FAIL", "legacy settings.users found; rerun apply to recreate with settings.clients")
	} else {
		add("hysteria2 clients", "FAIL", "expected settings.clients with a Hysteria2 auth client")
	}
	if hysteriaAuthPresent(inbound.StreamSettings) {
		add("hysteria2 auth", "PASS", "hysteriaSettings.auth is present")
	} else {
		add("hysteria2 auth", "FAIL", "expected hysteriaSettings.auth to mirror the client auth")
	}
	if alpnIsH3(inbound.StreamSettings) {
		add("hysteria2 alpn", "PASS", `tlsSettings.alpn is ["h3"]`)
	} else {
		add("hysteria2 alpn", "FAIL", "expected tlsSettings.alpn to be [h3]")
	}
	if salamanderObfsPresent(inbound.StreamSettings) {
		add("hysteria2 obfs", "PASS", "Salamander obfs password is configured")
	} else {
		add("hysteria2 obfs", "FAIL", "expected finalmask Salamander obfs password")
	}
}

func addShadowsocksConfigChecks(add func(string, string, string), inbounds []Inbound) {
	inbound, ok := shadowsocksInbound(inbounds)
	if !ok {
		add("shadowsocks config", "FAIL", "managed Shadowsocks inbound not found")
		return
	}
	if fmt.Sprint(settingValue(inbound.Settings, "method")) == shadowsocksMethod() {
		add("shadowsocks method", "PASS", shadowsocksMethod())
	} else {
		add("shadowsocks method", "FAIL", "expected "+shadowsocksMethod())
	}
	if nonEmptySetting(inbound.Settings, "password") {
		add("shadowsocks server password", "PASS", "settings.password is present")
	} else {
		add("shadowsocks server password", "FAIL", "expected settings.password")
	}
	if fmt.Sprint(settingValue(inbound.Settings, "network")) == "tcp,udp" {
		add("shadowsocks network", "PASS", "settings.network is tcp,udp")
	} else {
		add("shadowsocks network", "FAIL", "expected settings.network tcp,udp")
	}
	if shadowsocksClientPasswordPresent(inbound.Settings) {
		add("shadowsocks client password", "PASS", "settings.clients[0].password is present")
	} else {
		add("shadowsocks client password", "FAIL", "expected client password in settings.clients")
	}
}

func hysteria2Inbound(inbounds []Inbound) (Inbound, bool) {
	for _, inbound := range inbounds {
		if inbound.Tag == "wdns-hysteria2" || inbound.Protocol == "hysteria" && inbound.Port == 443 {
			return inbound, true
		}
	}
	return Inbound{}, false
}

func shadowsocksInbound(inbounds []Inbound) (Inbound, bool) {
	for _, inbound := range inbounds {
		if inbound.Tag == "wdns-shadowsocks" || inbound.Protocol == "shadowsocks" && inbound.Port == 8388 {
			return inbound, true
		}
	}
	return Inbound{}, false
}

func settingValue(value map[string]any, key string) any {
	data, _ := json.Marshal(value)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}
	return parsed[key]
}

func nonEmptySetting(value map[string]any, key string) bool {
	got := strings.TrimSpace(fmt.Sprint(settingValue(value, key)))
	return got != "" && got != "<nil>"
}

func shadowsocksClientPasswordPresent(settings map[string]any) bool {
	data, _ := json.Marshal(settings)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false
	}
	clients, _ := parsed["clients"].([]any)
	for _, raw := range clients {
		client, _ := raw.(map[string]any)
		password := strings.TrimSpace(fmt.Sprint(client["password"]))
		if password != "" && password != "<nil>" {
			return true
		}
	}
	return false
}

func torOutboundPresent(config map[string]any) bool {
	for _, outbound := range outbounds(config) {
		if fmt.Sprint(outbound["tag"]) != "wdns-tor" || fmt.Sprint(outbound["protocol"]) != "socks" {
			continue
		}
		settings, _ := outbound["settings"].(map[string]any)
		servers := anySlice(settings["servers"])
		for _, raw := range servers {
			server, _ := raw.(map[string]any)
			if fmt.Sprint(server["address"]) == "tor" && fmt.Sprint(server["port"]) == "9050" {
				return true
			}
		}
	}
	return false
}

func missingTorRoutingTags(config map[string]any) []string {
	found := map[string]bool{}
	routing, _ := config["routing"].(map[string]any)
	if routing == nil {
		return torInboundTags()
	}
	for _, rule := range routingRules(routing) {
		if fmt.Sprint(rule["outboundTag"]) != "wdns-tor" {
			continue
		}
		for _, tag := range stringList(rule["inboundTag"]) {
			found[tag] = true
		}
	}
	var missing []string
	for _, tag := range torInboundTags() {
		if !found[tag] {
			missing = append(missing, tag)
		}
	}
	return missing
}

func anySlice(value any) []any {
	switch got := value.(type) {
	case []any:
		return got
	case []map[string]any:
		out := make([]any, 0, len(got))
		for _, item := range got {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func stringList(value any) []string {
	switch got := value.(type) {
	case string:
		if strings.TrimSpace(got) == "" {
			return nil
		}
		return []string{got}
	case []string:
		return got
	case []any:
		var out []string
		for _, item := range got {
			if strings.TrimSpace(fmt.Sprint(item)) != "" {
				out = append(out, fmt.Sprint(item))
			}
		}
		return out
	default:
		return nil
	}
}

func hasArrayKey(value map[string]any, key string) bool {
	data, _ := json.Marshal(value)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false
	}
	raw, ok := parsed[key].([]any)
	return ok && len(raw) > 0
}

func alpnIsH3(streamSettings map[string]any) bool {
	data, _ := json.Marshal(streamSettings)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false
	}
	tlsSettings, _ := parsed["tlsSettings"].(map[string]any)
	raw, _ := tlsSettings["alpn"].([]any)
	if len(raw) != 1 {
		return false
	}
	return fmt.Sprint(raw[0]) == "h3"
}

func hysteriaAuthPresent(streamSettings map[string]any) bool {
	data, _ := json.Marshal(streamSettings)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false
	}
	hysteriaSettings, _ := parsed["hysteriaSettings"].(map[string]any)
	auth := strings.TrimSpace(fmt.Sprint(hysteriaSettings["auth"]))
	return auth != "" && auth != "<nil>"
}

func salamanderObfsPresent(streamSettings map[string]any) bool {
	data, _ := json.Marshal(streamSettings)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false
	}
	finalmask, _ := parsed["finalmask"].(map[string]any)
	udp, _ := finalmask["udp"].([]any)
	if len(udp) == 0 {
		return false
	}
	item, _ := udp[0].(map[string]any)
	if fmt.Sprint(item["type"]) != "salamander" {
		return false
	}
	settings, _ := item["settings"].(map[string]any)
	password := strings.TrimSpace(fmt.Sprint(settings["password"]))
	if password == "" || password == "<nil>" {
		return false
	}
	quicParams, _ := finalmask["quicParams"].(map[string]any)
	return fmt.Sprint(quicParams["congestion"]) == "bbr"
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func firstLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func portHost(domain string, port int) string {
	switch port {
	case PanelPort:
		return "panel." + domain
	case 443:
		return "vpn." + domain
	case 8443:
		return "trojan." + domain
	case 2083:
		return "reality." + domain
	case 2087:
		return "direct." + domain
	case 8388:
		return "ss." + domain
	case 2097:
		return "tor-vless-ws." + domain
	case 2098:
		return "tor-vless-ws-8443." + domain
	case 2100:
		return "tor-direct." + domain
	case 2101:
		return "tor-reality." + domain
	case 8390:
		return "tor-ss." + domain
	default:
		return domain
	}
}

func tcpStatus(host string, port int) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 4*time.Second)
	if err != nil {
		return "FAIL"
	}
	_ = conn.Close()
	return "PASS"
}

func certificateExpiry(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM certificate in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func copyDir(src, dst string, skipNames ...string) error {
	skip := map[string]bool{}
	for _, name := range skipNames {
		skip[name] = true
	}
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if path != src && skip[name] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func latestBackupDir(projectDir string) (string, error) {
	root := filepath.Join(projectDir, "backups")
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read backups directory: %w", err)
	}
	var backups []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "backup-") {
			backups = append(backups, filepath.Join(root, entry.Name()))
		}
	}
	if len(backups) == 0 {
		return "", fmt.Errorf("no backups found in %s", root)
	}
	sort.Strings(backups)
	return backups[len(backups)-1], nil
}

func (p Provisioner) openPanel(ctx context.Context, input Input) (projectData, Remote, Tunnel, *APIClient, error) {
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return projectData{}, nil, Tunnel{}, nil, err
	}
	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		return projectData{}, nil, Tunnel{}, nil, err
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		return projectData{}, nil, Tunnel{}, nil, err
	}
	tunnel, err := remote.Tunnel(ctx, "127.0.0.1", PanelPort)
	if err != nil {
		_ = remote.Close()
		return projectData{}, nil, Tunnel{}, nil, err
	}
	panel := panelFromInputOrSecrets(input.Panel, project.Secrets)
	apiFactory := p.APIClient
	if apiFactory == nil {
		apiFactory = NewAPIClient
	}
	api, err := apiFactory("http://"+tunnel.LocalAddr, panel.WebBasePath)
	if err != nil {
		_ = tunnel.Close()
		_ = remote.Close()
		return projectData{}, nil, Tunnel{}, nil, err
	}
	if err := retry(ctx, 3, time.Second, func() error {
		return api.Login(ctx, panel.Username, panel.Password)
	}); err != nil {
		_ = tunnel.Close()
		_ = remote.Close()
		return projectData{}, nil, Tunnel{}, nil, fmt.Errorf("login to 3x-ui panel: %w", err)
	}
	return project, remote, tunnel, api, nil
}

func (p Provisioner) deleteManagedPanelEntries(ctx context.Context, input Input, project projectData, remote Remote, result *DeleteResult) error {
	tunnel, err := remote.Tunnel(ctx, "127.0.0.1", PanelPort)
	if err != nil {
		return err
	}
	defer tunnel.Close()
	panel := panelFromInputOrSecrets(input.Panel, project.Secrets)
	apiFactory := p.APIClient
	if apiFactory == nil {
		apiFactory = NewAPIClient
	}
	api, err := apiFactory("http://"+tunnel.LocalAddr, panel.WebBasePath)
	if err != nil {
		return err
	}
	if err := api.Login(ctx, panel.Username, panel.Password); err != nil {
		return err
	}
	inbounds, err := api.ListInbounds(ctx)
	if err != nil {
		return err
	}
	for _, id := range managedInboundIDs(inbounds) {
		if err := api.DeleteInbound(ctx, id); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Could not delete inbound %d: %s", id, err))
			continue
		}
		result.DeletedInbounds++
	}
	config, outboundTestURL, err := api.GetXrayConfig(ctx)
	if err != nil {
		return err
	}
	before := len(outbounds(config))
	config = RemoveManagedOutbounds(config)
	result.RemovedOutbounds = before - len(outbounds(config))
	if result.RemovedOutbounds > 0 {
		if err := api.UpdateXrayConfig(ctx, config, outboundTestURL); err != nil {
			return err
		}
	}
	_ = api.RestartXray(ctx)
	return nil
}

func projectSummary(paths output.ProjectPaths, domain string) (ProjectSummary, error) {
	config, err := readYAMLFile[types.ProjectConfig](paths.Config)
	if err != nil {
		return ProjectSummary{}, err
	}
	cfState, _ := readJSONFile[types.CloudflareState](paths.CloudflareState)
	xuiState, _ := readJSONFile[types.XUIState](paths.XUIState)
	xuiPlan, _ := readYAMLFile[types.XUIPlan](paths.XUIPlan)
	lastApplied := cfState.AppliedAt
	if !xuiState.AppliedAt.IsZero() {
		lastApplied = xuiState.AppliedAt
	}
	return ProjectSummary{
		Domain:      domain,
		ProjectDir:  paths.ProjectDir,
		VPSIP:       config.VPSIP,
		SSHHost:     firstNonEmpty(xuiState.RemoteHost, config.VPSIP),
		SSHPort:     xuiPlan.Remote.SSHPort,
		ZoneStatus:  cfState.Zone.Status,
		LastApplied: lastApplied,
	}, nil
}

func summarizeInbound(inbound Inbound) InboundSummary {
	return InboundSummary{
		ID:       inbound.ID,
		Enabled:  inbound.Enable,
		Remark:   firstNonEmpty(inbound.Remark, inbound.Tag),
		Protocol: inbound.Protocol,
		Port:     inbound.Port,
		Network:  fmt.Sprint(inbound.StreamSettings["network"]),
		Security: fmt.Sprint(inbound.StreamSettings["security"]),
		Clients:  len(clientsFromSettings(inbound.Settings)),
	}
}

func clientsFromSettings(settings map[string]any) []map[string]any {
	data, _ := json.Marshal(settings)
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}
	var clients []map[string]any
	for _, key := range []string{"clients", "users"} {
		raw, _ := parsed[key].([]any)
		for _, item := range raw {
			if client, ok := item.(map[string]any); ok {
				clients = append(clients, client)
			}
		}
	}
	return clients
}

func summarizeClient(inbound string, client map[string]any) ClientSummary {
	return ClientSummary{
		Inbound:    inbound,
		Email:      fmt.Sprint(client["email"]),
		Enabled:    enabledValue(client["enable"]),
		Identifier: clientIdentifier(client),
		ExpiryTime: int64Value(client["expiryTime"]),
		TotalGB:    int64Value(client["totalGB"]),
	}
}

func clientIdentifier(client map[string]any) string {
	if id := strings.TrimSpace(fmt.Sprint(client["id"])); id != "" && id != "<nil>" {
		return id
	}
	auth := strings.TrimSpace(fmt.Sprint(client["auth"]))
	if auth == "" || auth == "<nil>" {
		return ""
	}
	if len(auth) <= 6 {
		return "auth:***"
	}
	return "auth:***" + auth[len(auth)-4:]
}

func boolValue(value any) bool {
	got, ok := value.(bool)
	return ok && got
}

func enabledValue(value any) bool {
	if value == nil {
		return true
	}
	got, ok := value.(bool)
	return !ok || got
}

func int64Value(value any) int64 {
	switch got := value.(type) {
	case int64:
		return got
	case int:
		return int64(got)
	case float64:
		return int64(got)
	default:
		return 0
	}
}

func generatedFromValues(values map[string]string) secrets.GeneratedSecrets {
	return secrets.GeneratedSecrets{
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
		TorRealitySNI:          values["tor_reality_sni"],
		VLESSWSPath:            values["vless_ws_path"],
		TrojanWSPath:           values["trojan_ws_path"],
		PostgresPassword:       values["postgres_password"],
		PanelUsername:          values["panel_username"],
		PanelPassword:          values["panel_password"],
		PanelBasePath:          values["panel_base_path"],
	}
}

func readYAMLFile[T any](path string) (T, error) {
	var value T
	data, err := os.ReadFile(path)
	if err != nil {
		return value, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if err := yaml.Unmarshal(data, &value); err != nil {
		return value, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return value, nil
}

func readJSONFile[T any](path string) (T, error) {
	var value T
	data, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return value, nil
}
