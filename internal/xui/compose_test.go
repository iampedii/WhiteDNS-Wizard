package xui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRemote struct {
	commands []string
	uploads  map[string][]byte
	results  map[string]error
	outputs  map[string]string
	failOnce map[string]error
}

func (r *fakeRemote) Run(ctx context.Context, command string) (string, error) {
	r.commands = append(r.commands, command)
	for pattern, err := range r.failOnce {
		if strings.Contains(command, pattern) {
			delete(r.failOnce, pattern)
			return "", err
		}
	}
	for pattern, output := range r.outputs {
		if strings.Contains(command, pattern) {
			return output, nil
		}
	}
	if r.results != nil {
		if err, ok := r.results[command]; ok {
			return "", err
		}
	}
	return "", nil
}

func (r *fakeRemote) Upload(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	if r.uploads == nil {
		r.uploads = map[string][]byte{}
	}
	r.uploads[path] = data
	return nil
}

func (r *fakeRemote) Tunnel(ctx context.Context, remoteHost string, remotePort int) (Tunnel, error) {
	return Tunnel{}, nil
}

func (r *fakeRemote) Close() error {
	return nil
}

func TestRenderComposeDoesNotProfilePostgres(t *testing.T) {
	compose := RenderCompose("pg-secret")
	if strings.Contains(compose, `profiles: ["postgres"]`) {
		t.Fatalf("compose should not put postgres behind a profile:\n%s", compose)
	}
	assertContains(t, compose, "depends_on:\n      - postgres")
	assertContains(t, compose, "      - tor")
	assertContains(t, compose, "container_name: 3xui_tor")
	if strings.Contains(compose, "9050:9050") {
		t.Fatalf("compose should not publish tor socks port:\n%s", compose)
	}
}

func TestProgressRecorderWritesLogFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "logs", "xui-provision.log")
	recorder := newProgressRecorder(nil)
	recorder.Log("Preparing project.")
	recorder.SetPath(logPath)
	recorder.Log("Applying firewall rules.")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read progress log: %v", err)
	}
	body := string(data)
	assertContains(t, body, "Preparing project.")
	assertContains(t, body, "Applying firewall rules.")
}

func TestInstallDocker3XUIInstallsComposePluginWhenMissing(t *testing.T) {
	remote := &fakeRemote{
		failOnce: map[string]error{
			"docker compose version >/dev/null 2>&1": fmt.Errorf("compose plugin missing"),
		},
	}
	err := InstallDocker3XUI(context.Background(), remote, map[string]string{
		"postgres_password": "pg-secret",
		"panel_username":    "admin",
		"panel_password":    "panel-secret",
		"panel_base_path":   "/panel/",
	})
	if err != nil {
		t.Fatalf("InstallDocker3XUI returned error: %v", err)
	}
	if len(remote.commands) < 4 {
		t.Fatalf("commands = %+v, want compose install path", remote.commands)
	}
	if remote.commands[1] != "docker compose version >/dev/null 2>&1" {
		t.Fatalf("unexpected compose check command: %+v", remote.commands)
	}
	assertContains(t, remote.commands[2], "apt-get install -y docker-compose-plugin")
	assertContains(t, remote.commands[2], "dnf install -y docker-compose-plugin")
	assertContains(t, remote.commands[2], "yum install -y docker-compose-plugin")
	assertContains(t, remote.commands[2], "apk add --no-cache docker-cli-compose")
	assertContains(t, remote.commands[2], `x86_64|amd64) compose_arch="x86_64"`)
	assertContains(t, remote.commands[2], `aarch64|arm64) compose_arch="aarch64"`)
	assertContains(t, remote.commands[2], `https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$compose_arch`)
	assertContains(t, remote.commands[2], `/usr/local/lib/docker/cli-plugins`)
	assertContains(t, remote.commands[2], `install -m 0755 "$tmp_path" "$plugin_path"`)
	if remote.commands[3] != "docker compose version >/dev/null 2>&1" {
		t.Fatalf("compose plugin should be rechecked after install: %+v", remote.commands)
	}
}

func TestEnsureManagedDocker3XUIUsesProfileSafeCommands(t *testing.T) {
	remote := &fakeRemote{}
	err := EnsureManagedDocker3XUI(context.Background(), remote, map[string]string{
		"postgres_password": "pg-secret",
		"panel_username":    "admin",
		"panel_password":    "panel-secret",
		"panel_base_path":   "/panel/",
	})
	if err != nil {
		t.Fatalf("EnsureManagedDocker3XUI returned error: %v", err)
	}
	if len(remote.uploads[RemoteComposePath]) == 0 {
		t.Fatal("expected compose upload")
	}
	if len(remote.uploads[RemoteTorDockerfilePath]) == 0 {
		t.Fatal("expected tor Dockerfile upload")
	}
	if len(remote.uploads[RemoteTorrcPath]) == 0 {
		t.Fatal("expected torrc upload")
	}
	joined := strings.Join(remote.commands, "\n")
	postgresStart := indexComposeTestCommandContaining(remote.commands, "docker compose --profile postgres up -d postgres")
	postgresRepair := indexComposeTestCommandContaining(remote.commands, "docker compose --profile postgres exec -T postgres")
	appStart := indexComposeTestCommandContaining(remote.commands, "docker compose --profile postgres up -d --force-recreate --no-deps 3xui")
	if postgresStart == -1 || postgresRepair == -1 || appStart == -1 {
		t.Fatalf("expected postgres start, postgres repair, and app start commands:\n%s", joined)
	}
	if !(postgresStart < postgresRepair && postgresRepair < appStart) {
		t.Fatalf("postgres password should be synced before app start:\n%s", joined)
	}
	assertContains(t, joined, "docker compose --profile postgres up -d --build tor")
	assertContains(t, joined, "docker compose --profile postgres exec -T 3xui")
	assertContains(t, joined, "docker compose --profile postgres restart 3xui")
}

func TestApplyFirewallAllowsPublicPanelPort(t *testing.T) {
	remote := &fakeRemote{}
	warnings := ApplyFirewall(context.Background(), remote)
	if len(warnings) != 0 {
		t.Fatalf("ApplyFirewall warnings = %+v, want none", warnings)
	}
	joined := strings.Join(remote.commands, "\n")
	assertContains(t, joined, "ufw allow 2053/tcp")
	assertContains(t, joined, "ufw allow 8388/tcp")
	assertContains(t, joined, "ufw allow 8388/udp")
	assertContains(t, joined, "ufw allow 2097/tcp")
	assertContains(t, joined, "ufw allow 2099/udp")
	assertContains(t, joined, "ufw allow 8390/tcp")
	assertContains(t, joined, "ufw allow 8390/udp")
	assertContains(t, joined, "ufw allow 8080/tcp")
	assertContains(t, joined, "ufw allow 56201/tcp")
	assertContains(t, joined, "ufw allow 56207/tcp")
}

func TestApplyFirewallWarningIncludesPublicPanelPort(t *testing.T) {
	inactive := fmt.Errorf("inactive")
	remote := &fakeRemote{results: map[string]error{
		"command -v ufw >/dev/null 2>&1 && ufw status | grep -qi active":                  inactive,
		"command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1": inactive,
	}}
	warnings := ApplyFirewall(context.Background(), remote)
	if len(warnings) != 1 {
		t.Fatalf("ApplyFirewall warnings = %+v, want one warning", warnings)
	}
	assertContains(t, warnings[0], "2053/tcp")
	assertContains(t, warnings[0], "8388/tcp")
	assertContains(t, warnings[0], "8388/udp")
	assertContains(t, warnings[0], "2097/tcp")
	assertContains(t, warnings[0], "2099/udp")
	assertContains(t, warnings[0], "8390/tcp")
	assertContains(t, warnings[0], "8390/udp")
}

func TestEnsureManagedDocker3XUIRecoversPostgresPasswordMismatch(t *testing.T) {
	remote := &fakeRemote{
		outputs: map[string]string{
			"docker logs --tail 120 3xui_app": `Error initializing database: failed SASL auth: FATAL: password authentication failed for user "xui"`,
		},
	}
	err := EnsureManagedDocker3XUI(context.Background(), remote, map[string]string{
		"postgres_password": "pg-secret",
		"panel_username":    "admin",
		"panel_password":    "panel-secret",
		"panel_base_path":   "/panel/",
	})
	if err != nil {
		t.Fatalf("EnsureManagedDocker3XUI returned error: %v", err)
	}
	joined := strings.Join(remote.commands, "\n")
	assertContains(t, joined, "docker logs --tail 120 3xui_app")
	assertContains(t, joined, "docker compose --profile postgres down")
	assertContains(t, joined, "mv ./pgdata ./pgdata.backup.$(date -u +%Y%m%d-%H%M%S)")
	assertContains(t, joined, "docker compose --profile postgres up -d postgres")
	assertContains(t, joined, "ALTER USER xui WITH PASSWORD")
	assertContains(t, joined, "docker compose --profile postgres up -d --build tor")
	assertContains(t, joined, "docker compose --profile postgres up -d --force-recreate --no-deps 3xui")
	assertContains(t, joined, "docker compose --profile postgres exec -T 3xui")
}

func TestEnsureManagedDocker3XUIRetriesTransientConfigureFailure(t *testing.T) {
	remote := &fakeRemote{
		failOnce: map[string]error{
			"docker compose --profile postgres exec -T 3xui": fmt.Errorf("remote command failed: container is restarting, wait until the container is running"),
		},
		outputs: map[string]string{
			"docker logs --tail 120 3xui_app": ``,
		},
	}
	err := EnsureManagedDocker3XUI(context.Background(), remote, map[string]string{
		"postgres_password": "pg-secret",
		"panel_username":    "admin",
		"panel_password":    "panel-secret",
		"panel_base_path":   "/panel/",
	})
	if err != nil {
		t.Fatalf("EnsureManagedDocker3XUI returned error: %v", err)
	}
	joined := strings.Join(remote.commands, "\n")
	if strings.Contains(joined, "mv ./pgdata") {
		t.Fatalf("non-auth transient configure failure should not recreate pgdata\n%s", joined)
	}
	if got := strings.Count(joined, "docker compose --profile postgres exec -T 3xui"); got != 2 {
		t.Fatalf("credential configuration attempts = %d, want 2\n%s", got, joined)
	}
}

func indexComposeTestCommandContaining(commands []string, want string) int {
	for i, command := range commands {
		if strings.Contains(command, want) {
			return i
		}
	}
	return -1
}
