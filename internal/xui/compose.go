package xui

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func RenderCompose(postgresPassword string) string {
	return fmt.Sprintf(`services:
  3xui:
    image: ghcr.io/mhsanaei/3x-ui:latest
    container_name: 3xui_app
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./db/:/etc/x-ui/
      - ./cert/:/root/cert/
    environment:
      XRAY_VMESS_AEAD_FORCED: "false"
      XUI_ENABLE_FAIL2BAN: "true"
      XUI_DB_TYPE: "postgres"
      XUI_DB_DSN: "postgres://xui:%s@postgres:5432/xui?sslmode=disable"
    tty: true
    ports:
      - "2053:2053/tcp"
      - "443:443/tcp"
      - "443:443/udp"
      - "8443:8443/tcp"
      - "2087:2087/tcp"
      - "2083:2083/tcp"
      - "8388:8388/tcp"
      - "8388:8388/udp"
      - "2097:2097/tcp"
      - "2098:2098/tcp"
      - "2099:2099/udp"
      - "2100:2100/tcp"
      - "2101:2101/tcp"
      - "8390:8390/tcp"
      - "8390:8390/udp"
	  - "2096:2096/tcp"
	  - "2096:2096/udp"
    restart: unless-stopped
    depends_on:
      - postgres
      - tor
  tor:
    build:
      context: ./tor
    container_name: 3xui_tor
    restart: unless-stopped
  postgres:
    image: postgres:16-alpine
    container_name: 3xui_postgres
    environment:
      POSTGRES_USER: xui
      POSTGRES_PASSWORD: %s
      POSTGRES_DB: xui
    volumes:
      - ./pgdata/:/var/lib/postgresql/data
    restart: unless-stopped
`, postgresPassword, postgresPassword)
}

func RenderTorDockerfile() string {
	return `FROM alpine:3.24
RUN apk add --no-cache tor && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
`
}

func RenderTorrc() string {
	return `SocksPort 0.0.0.0:9050
SocksPolicy accept *
Log notice stdout
DataDirectory /var/lib/tor
`
}

func DetectRemote(ctx context.Context, remote Remote) (RemoteInfo, error) {
	var info RemoteInfo
	if _, err := remote.Run(ctx, "command -v docker >/dev/null 2>&1"); err == nil {
		info.DockerInstalled = true
	}
	if info.DockerInstalled {
		if _, err := remote.Run(ctx, "docker compose version >/dev/null 2>&1"); err == nil {
			info.DockerComposeInstalled = true
		}
		out, err := remote.Run(ctx, "docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}'")
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				parts := strings.Split(line, "|")
				if len(parts) < 3 {
					continue
				}
				image := strings.ToLower(parts[1])
				name := parts[2]
				if strings.Contains(image, "mhsanaei/3x-ui") || name == "3xui_app" || name == "3x-ui" {
					info.ExistingDocker3XUI = true
					info.ContainerName = name
					info.Image = parts[1]
					break
				}
			}
		}
	}
	if _, err := remote.Run(ctx, "test -f "+shQuote(RemoteComposePath)); err == nil {
		info.ManagedDocker3XUI = true
	} else if _, err := remote.Run(ctx, "test -f "+shQuote(OldRemoteBaseDir+"/docker-compose.yml")); err == nil {
		info.ManagedDocker3XUI = true
		info.Warnings = append(info.Warnings, "Legacy managed path detected at "+OldRemoteBaseDir+". Apply will migrate it to "+RemoteBaseDir+".")
	}
	if _, err := remote.Run(ctx, "command -v x-ui >/dev/null 2>&1 || systemctl is-active --quiet x-ui"); err == nil && !info.ExistingDocker3XUI {
		info.ExistingNonDockerXUI = true
		info.Warnings = append(info.Warnings, "A non-Docker 3x-ui/x-ui install was detected. Automatic migration is not supported.")
	}
	if !info.DockerInstalled {
		info.Warnings = append(info.Warnings, "Docker is not installed. The wizard will install Docker before installing 3x-ui.")
	}
	if info.DockerInstalled && !info.DockerComposeInstalled {
		info.Warnings = append(info.Warnings, "Docker Compose plugin is not available. Apply will try package-manager installs first, then the official Compose v2 plugin binary.")
	}
	return info, nil
}

func InstallDocker3XUI(ctx context.Context, remote Remote, values map[string]string) error {
	if _, err := remote.Run(ctx, "command -v docker >/dev/null 2>&1"); err != nil {
		if _, err := remote.Run(ctx, "curl -fsSL https://get.docker.com -o /tmp/wdns-get-docker.sh && sh /tmp/wdns-get-docker.sh"); err != nil {
			return fmt.Errorf("install Docker: %w", err)
		}
	}
	if err := ensureDockerComposePlugin(ctx, remote); err != nil {
		return err
	}
	return EnsureManagedDocker3XUI(ctx, remote, values)
}

func ensureDockerComposePlugin(ctx context.Context, remote Remote) error {
	if _, err := remote.Run(ctx, "docker compose version >/dev/null 2>&1"); err == nil {
		return nil
	}
	if _, err := remote.Run(ctx, dockerComposePluginInstallCommand()); err != nil {
		return fmt.Errorf("install Docker Compose plugin: %w", err)
	}
	if _, err := remote.Run(ctx, "docker compose version >/dev/null 2>&1"); err != nil {
		return fmt.Errorf("Docker Compose plugin is required after installation attempt: %w", err)
	}
	return nil
}

func dockerComposePluginInstallCommand() string {
	script := `set -u
if docker compose version >/dev/null 2>&1; then
  exit 0
fi

install_from_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update || true
    apt-get install -y docker-compose-plugin && return 0
  fi
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y docker-compose-plugin && return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    yum install -y docker-compose-plugin && return 0
  fi
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache docker-cli-compose && return 0
  fi
  return 1
}

install_from_package_manager || true
if docker compose version >/dev/null 2>&1; then
  exit 0
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) compose_arch="x86_64" ;;
  aarch64|arm64) compose_arch="aarch64" ;;
  armv7l|armv7) compose_arch="armv7" ;;
  s390x) compose_arch="s390x" ;;
  ppc64le) compose_arch="ppc64le" ;;
  *) echo "Unsupported CPU architecture for Docker Compose plugin: $arch" >&2; exit 1 ;;
esac

plugin_dir="/usr/local/lib/docker/cli-plugins"
plugin_path="$plugin_dir/docker-compose"
download_url="https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$compose_arch"
tmp_path="/tmp/wdns-docker-compose"
mkdir -p "$plugin_dir"

ensure_downloader() {
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update || true
    apt-get install -y ca-certificates curl || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ca-certificates curl || true
  fi
}

ensure_downloader
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$download_url" -o "$tmp_path" || exit 1
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp_path" "$download_url" || exit 1
else
  echo "curl or wget is required to download Docker Compose plugin" >&2
  exit 1
fi
install -m 0755 "$tmp_path" "$plugin_path" || exit 1
rm -f "$tmp_path"
docker compose version >/dev/null 2>&1`
	return "sh -lc " + shQuote(script)
}

func EnsureManagedDocker3XUI(ctx context.Context, remote Remote, values map[string]string) error {
	if err := PrepareManagedDocker3XUI(ctx, remote); err != nil {
		return err
	}
	compose := RenderCompose(values["postgres_password"])
	if err := remote.Upload(ctx, RemoteComposePath, []byte(compose), 0o644); err != nil {
		return err
	}
	if err := remote.Upload(ctx, RemoteTorDockerfilePath, []byte(RenderTorDockerfile()), 0o644); err != nil {
		return err
	}
	if err := remote.Upload(ctx, RemoteTorrcPath, []byte(RenderTorrc()), 0o644); err != nil {
		return err
	}
	if err := startManagedDocker3XUI(ctx, remote, values["postgres_password"]); err != nil {
		return err
	}
	if managedPostgresAuthFailureFromLogs(ctx, remote) {
		if err := recoverAndRestartManagedDocker3XUI(ctx, remote, values["postgres_password"]); err != nil {
			return err
		}
	}
	if err := retry(ctx, 60, time.Second, func() error {
		return ConfigurePanelCredentials(ctx, remote, values)
	}); err != nil {
		if managedPostgresAuthFailure(ctx, remote, err) {
			if recoverErr := recoverAndRestartManagedDocker3XUI(ctx, remote, values["postgres_password"]); recoverErr != nil {
				return fmt.Errorf("recover managed postgres data after 3x-ui database auth failure: %w", recoverErr)
			}
			if retryErr := retry(ctx, 60, time.Second, func() error {
				return ConfigurePanelCredentials(ctx, remote, values)
			}); retryErr != nil {
				return retryErr
			}
			return nil
		}
		return err
	}
	return nil
}

func PrepareManagedDocker3XUI(ctx context.Context, remote Remote) error {
	if _, err := remote.Run(ctx, "sh -lc "+shQuote(prepareManagedDocker3XUIScript())); err != nil {
		return fmt.Errorf("prepare managed 3x-ui remote directory: %w", err)
	}
	return nil
}

func prepareManagedDocker3XUIScript() string {
	return "set -u\n" +
		"base=" + shQuote(RemoteBaseDir) + "\n" +
		"old_base=" + shQuote(OldRemoteBaseDir) + "\n" +
		"tor_dir=" + shQuote(RemoteBaseDir+"/tor") + "\n" +
		"db_dir=" + shQuote(RemoteBaseDir+"/db") + "\n" +
		"cert_dir=" + shQuote(RemoteBaseDir+"/cert") + "\n" +
		"cert_wdns_dir=" + shQuote(RemoteBaseDir+"/cert/wdns") + "\n" +
		"pgdata_dir=" + shQuote(RemoteBaseDir+"/pgdata") + "\n" +
		"if [ ! -d \"$base\" ] && [ -d \"$old_base\" ]; then\n" +
		"  if [ -f \"$old_base/docker-compose.yml\" ]; then\n" +
		"    (cd \"$old_base\" && docker compose --profile postgres down) || true\n" +
		"  fi\n" +
		"  if mkdir -p " + shQuote("/var/lib/whitedns") + " && mv \"$old_base\" \"$base\"; then\n" +
		"    echo \"migrated managed directory from $old_base to $base\"\n" +
		"  else\n" +
		"    echo \"warning: could not migrate old managed directory from $old_base to $base; continuing with fresh directory\" >&2\n" +
		"  fi\n" +
		"fi\n" +
		"if ! mkdir -p \"$base\" \"$tor_dir\" \"$db_dir\" \"$cert_dir\" \"$cert_wdns_dir\" \"$pgdata_dir\"; then\n" +
		"  echo \"remote managed directory is not writable: $base\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"for dir in \"$base\" \"$tor_dir\" \"$db_dir\" \"$cert_dir\" \"$cert_wdns_dir\" \"$pgdata_dir\"; do\n" +
		"  if [ ! -d \"$dir\" ]; then\n" +
		"    echo \"remote managed directory was not created: $dir\" >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"  if [ ! -w \"$dir\" ]; then\n" +
		"    echo \"remote managed directory is not writable: $dir\" >&2\n" +
		"    exit 1\n" +
		"  fi\n" +
		"done"
}

func startManagedDocker3XUI(ctx context.Context, remote Remote, postgresPassword string) error {
	if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres up -d postgres"); err != nil {
		return fmt.Errorf("start 3x-ui postgres service: %w", err)
	}
	if err := RepairManagedPostgresPassword(ctx, remote, postgresPassword); err != nil {
		return fmt.Errorf("sync managed postgres password before 3x-ui start: %w", err)
	}
	if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres up -d --build tor"); err != nil {
		return fmt.Errorf("start 3x-ui tor service: %w", err)
	}
	if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres up -d --force-recreate --no-deps 3xui"); err != nil {
		return fmt.Errorf("start 3x-ui docker compose service: %w", err)
	}
	return nil
}

func recoverAndRestartManagedDocker3XUI(ctx context.Context, remote Remote, postgresPassword string) error {
	if err := RecoverManagedPostgres(ctx, remote); err != nil {
		return err
	}
	if err := startManagedDocker3XUI(ctx, remote, postgresPassword); err != nil {
		return fmt.Errorf("restart 3x-ui docker compose stack after postgres recovery: %w", err)
	}
	return nil
}

func ConfigurePanelCredentials(ctx context.Context, remote Remote, values map[string]string) error {
	if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres exec -T 3xui sh -lc "+shQuote("if [ -x /app/x-ui ]; then /app/x-ui setting -username "+shQuoteArg(values["panel_username"])+" -password "+shQuoteArg(values["panel_password"])+" -webBasePath "+shQuoteArg(values["panel_base_path"])+" -port 2053 >/dev/null 2>&1; else x-ui setting -username "+shQuoteArg(values["panel_username"])+" -password "+shQuoteArg(values["panel_password"])+" -webBasePath "+shQuoteArg(values["panel_base_path"])+" -port 2053 >/dev/null 2>&1; fi")); err != nil {
		return fmt.Errorf("configure 3x-ui panel credentials: %w", err)
	}
	if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres restart 3xui"); err != nil {
		return fmt.Errorf("restart 3x-ui panel: %w", err)
	}
	return nil
}

func RepairManagedPostgresPassword(ctx context.Context, remote Remote, postgresPassword string) error {
	sql := "ALTER USER xui WITH PASSWORD '" + strings.ReplaceAll(postgresPassword, "'", "''") + "';"
	script := "for i in $(seq 1 60); do psql -U xui -d xui -v ON_ERROR_STOP=1 -c " + shQuote(sql) + " && exit 0; sleep 1; done; exit 1"
	if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres exec -T postgres sh -lc "+shQuote(script)); err != nil {
		return fmt.Errorf("repair postgres xui password: %w", err)
	}
	return nil
}

func RecoverManagedPostgres(ctx context.Context, remote Remote) error {
	if _, err := remote.Run(ctx, "cd "+shQuote(RemoteBaseDir)+" && docker compose --profile postgres down"); err != nil {
		return fmt.Errorf("stop managed 3x-ui stack: %w", err)
	}
	cmd := "cd " + shQuote(RemoteBaseDir) + " && " +
		"if [ -d ./pgdata ]; then mv ./pgdata ./pgdata.backup.$(date -u +%Y%m%d-%H%M%S); fi && " +
		"mkdir -p ./pgdata"
	if _, err := remote.Run(ctx, cmd); err != nil {
		return fmt.Errorf("backup and recreate managed postgres data directory: %w", err)
	}
	return nil
}

func managedPostgresAuthFailure(ctx context.Context, remote Remote, err error) bool {
	lower := strings.ToLower(err.Error())
	if isManagedPostgresAuthFailureText(lower) {
		return true
	}
	if !strings.Contains(lower, "restarting") &&
		!strings.Contains(lower, "connection reset") &&
		!strings.Contains(lower, "database") {
		return false
	}
	return managedPostgresAuthFailureFromLogs(ctx, remote)
}

func managedPostgresAuthFailureFromLogs(ctx context.Context, remote Remote) bool {
	logs, logErr := remote.Run(ctx, "docker logs --tail 120 3xui_app 2>&1 || true")
	if logErr != nil {
		return false
	}
	return isManagedPostgresAuthFailureText(logs)
}

func isManagedPostgresAuthFailureText(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "password authentication failed") &&
		(strings.Contains(lower, `user "xui"`) || strings.Contains(lower, "user=xui"))
}

func shQuoteArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func ApplyFirewall(ctx context.Context, remote Remote) []string {
	var warnings []string
	if _, err := remote.Run(ctx, "command -v ufw >/dev/null 2>&1 && ufw status | grep -qi active"); err == nil {
		for _, rule := range publicFirewallRules() {
			if _, err := remote.Run(ctx, "ufw allow "+rule+" >/dev/null 2>&1"); err != nil {
				warnings = append(warnings, "Failed to allow "+rule+" with ufw: "+err.Error())
			}
		}
		return warnings
	}
	if _, err := remote.Run(ctx, "command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1"); err == nil {
		for _, rule := range publicFirewallRules() {
			if _, err := remote.Run(ctx, "firewall-cmd --permanent --add-port="+rule+" >/dev/null 2>&1"); err != nil {
				warnings = append(warnings, "Failed to allow "+rule+" with firewalld: "+err.Error())
			}
		}
		if _, err := remote.Run(ctx, "firewall-cmd --reload >/dev/null 2>&1"); err != nil {
			warnings = append(warnings, "Failed to reload firewalld: "+err.Error())
		}
		return warnings
	}
	warnings = append(warnings, "No active ufw or firewalld firewall was detected; verify VPS firewall rules allow "+strings.Join(publicFirewallRules(), ", ")+".")
	return warnings
}

func publicFirewallRules() []string {
	return []string{
		"2053/tcp",
		"443/tcp",
		"443/udp",
		"8443/tcp",
		"2087/tcp",
		"2083/tcp",
		"8388/tcp",
		"8388/udp",
		"2097/tcp",
		"2098/tcp",
		"2099/udp",
		"2100/tcp",
		"2101/tcp",
		"8390/tcp",
		"8390/udp",
	}
}
