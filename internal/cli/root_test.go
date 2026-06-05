package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whitedns/wdns-wizard/internal/app"
)

func TestRootWithoutSubcommandRunsWizard(t *testing.T) {
	originalRunTUI := runTUI
	defer func() { runTUI = originalRunTUI }()

	root := t.TempDir()
	called := false
	runTUI = func(provisioner app.Provisioner) error {
		called = true
		if provisioner.Root != root {
			t.Fatalf("Root = %q, want %q", provisioner.Root, root)
		}
		if provisioner.AccountID != "account-id" {
			t.Fatalf("AccountID = %q, want account-id", provisioner.AccountID)
		}
		return nil
	}

	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--root", root, "--account-id", "account-id"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !called {
		t.Fatal("root command did not launch wizard")
	}
}

func TestRootRejectsUnexpectedArgs(t *testing.T) {
	originalRunTUI := runTUI
	defer func() { runTUI = originalRunTUI }()
	runTUI = func(provisioner app.Provisioner) error {
		t.Fatal("root command should not launch wizard with unexpected args")
		return nil
	}

	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"unexpected"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected unexpected arg error")
	}
}

func TestRootHelpUsesWhiteDNSCommandName(t *testing.T) {
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "whitedns [flags]") || !strings.Contains(body, "whitedns [command]") {
		t.Fatalf("help did not use whitedns command name:\n%s", body)
	}
	if strings.Contains(body, "wdns-wizard [") {
		t.Fatalf("help still references old command name:\n%s", body)
	}
}

func TestRootVersionIncludesBuildMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, date
	defer func() {
		version, commit, date = oldVersion, oldCommit, oldDate
	}()
	version = "v9.9.9"
	commit = "abc123"
	date = "2026-06-05T00:00:00Z"

	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	want := "whitedns v9.9.9 commit=abc123 built=2026-06-05T00:00:00Z"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("version output = %q, want %q", out.String(), want)
	}
}

func TestPlanShow(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "example.com", "plans")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "dns-plan.yaml"), []byte("records: []\n"), 0o644); err != nil {
		t.Fatalf("write dns plan: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "protocol-plan.yaml"), []byte("protocols: []\n"), 0o644); err != nil {
		t.Fatalf("write protocol plan: %v", err)
	}

	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--root", root, "plan", "show", "Example.COM"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "# dns-plan.yaml") || !strings.Contains(got, "# protocol-plan.yaml") {
		t.Fatalf("unexpected output: %s", got)
	}
}

func TestCloudflareCheckRequiresTokenInNonInteractiveMode(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--root", t.TempDir(), "--account-id", "account-id", "cloudflare", "check"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Cloudflare API token is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIranPlanCommand(t *testing.T) {
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"iran", "plan",
		"--front-domain", "setup.azargate.ir",
		"--cdn-host", "cdn2.navaanet.ir",
		"--cdn-port", "2053",
		"--ws-front", "domain.iran243.ir",
		"--ws-address", "snapp.ir",
		"--ws-port", "8880",
		"--tcp-host", "edge.nextgen.ir",
		"--tcp-port", "56206",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "vless://") {
		t.Fatalf("iran plan did not print a client link:\n%s", body)
	}
	if !strings.Contains(body, "type=xhttp&security=tls") {
		t.Fatalf("iran plan missing the XHTTP-TLS link:\n%s", body)
	}
	if !strings.Contains(body, "host=setup.azargate.ir") || !strings.Contains(body, "sni=setup.azargate.ir") {
		t.Fatalf("iran plan XHTTP link must carry SNI==Host:\n%s", body)
	}
	if !strings.Contains(body, "Manual ArvanCloud checklist") {
		t.Fatalf("iran plan did not print the manual checklist:\n%s", body)
	}
	if strings.Contains(strings.ToLower(body), "cloudflare token") {
		t.Fatalf("iran plan must not require a Cloudflare token:\n%s", body)
	}
}

func TestIranPlanRejectsWSAddressEqualsFront(t *testing.T) {
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"iran", "plan",
		"--front-domain", "front.ir",
		"--ws-front", "decoy.ir",
		"--ws-address", "decoy.ir",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected validation error when ws address == host front")
	}
}

func TestIranCommandHelpHasNoCloudflareFlag(t *testing.T) {
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"iran", "plan", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "--front-domain") || !strings.Contains(body, "--cdn-host") {
		t.Fatalf("iran plan help missing fronting flags:\n%s", body)
	}
	if strings.Contains(body, "--token") {
		t.Fatalf("iran plan must not expose a Cloudflare --token flag:\n%s", body)
	}
}

func TestXUIApplyHelpIncludesSSHKeyPassphraseFlag(t *testing.T) {
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"xui", "apply", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(out.String(), "--ssh-key-passphrase") {
		t.Fatalf("help did not include ssh key passphrase flag: %s", out.String())
	}
}
