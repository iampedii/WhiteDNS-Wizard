package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/whitedns/wdns-wizard/internal/app"
	"github.com/whitedns/wdns-wizard/internal/credentials"
	"github.com/whitedns/wdns-wizard/internal/xui"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

func TestInitStartsAtMenu(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	if m.step != stepMenu {
		t.Fatalf("step = %v, want stepMenu", m.step)
	}
	view := m.View()
	if !strings.Contains(view, "0) Init setup") || !strings.Contains(view, "2) Diagnostics") || !strings.Contains(view, "x) Delete installation") {
		t.Fatalf("menu view missing expected entries:\n%s", view)
	}
	if !strings.Contains(view, "@whitedns") {
		t.Fatalf("menu view missing Telegram channel:\n%s", view)
	}
}

func TestMenuShowsIranItem(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	view := m.View()
	if !strings.Contains(view, "i) Iran domestic-fronting configs") {
		t.Fatalf("menu view missing Iran domestic-fronting item:\n%s", view)
	}
}

func TestMenuIranFrontingShowsProfiles(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	next, _ := m.handleMenuKey("i")
	got := next.(model)
	if got.menuAction != menuIranFronting {
		t.Fatalf("menuAction = %v, want menuIranFronting", got.menuAction)
	}
	if got.step != stepActionDetail || got.actionFailed {
		t.Fatalf("step/actionFailed = %v/%v, want successful detail", got.step, got.actionFailed)
	}
	view := got.View()
	if !strings.Contains(view, "type=xhttp&security=tls") {
		t.Fatalf("iran fronting view missing XHTTP-TLS link:\n%s", view)
	}
	if !strings.Contains(view, "Manual ArvanCloud checklist") {
		t.Fatalf("iran fronting view missing manual checklist:\n%s", view)
	}
}

func TestMenuOptionZeroEntersSetupWelcome(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	next, _ := m.handleMenuKey("0")
	got := next.(model)
	if got.step != stepWelcome {
		t.Fatalf("step = %v, want stepWelcome", got.step)
	}
}

func TestMenuDiagnosticsShortcutUsesProjectAction(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	next, _ := m.handleMenuKey("2")
	got := next.(model)

	if got.menuAction != menuDiagnostics {
		t.Fatalf("menuAction = %v, want menuDiagnostics", got.menuAction)
	}
	if got.step != stepActionDetail || !got.actionFailed {
		t.Fatalf("step/actionFailed = %v/%v, want missing-project detail", got.step, got.actionFailed)
	}
}

func TestInitWelcomeUsesSimpleLayoutWithStepIndicator(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	next, _ := m.handleMenuKey("0")
	got := next.(model)
	view := got.View()

	for _, border := range []string{"╭", "╮", "╰", "╯", "│"} {
		if strings.Contains(view, border) {
			t.Fatalf("init view should not render border character %q:\n%s", border, view)
		}
	}
	for _, want := range []string{"WhiteDNS", "@whitedns", "Setup:", "1 Cloudflare", "2 Domain", "6 Output"} {
		if !strings.Contains(view, want) {
			t.Fatalf("init view missing %q:\n%s", want, view)
		}
	}
}

func TestMenuUsesSimpleBorderlessLayout(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	view := m.View()

	for _, border := range []string{"╭", "╮", "╰", "╯", "│"} {
		if strings.Contains(view, border) {
			t.Fatalf("menu view should not render border character %q:\n%s", border, view)
		}
	}
	if strings.Contains(view, "__        ___") {
		t.Fatalf("menu should not render large ASCII logo:\n%s", view)
	}
}

func TestEscInSubmenuReturnsToMainMenu(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepProjectSelect
	m.menuAction = menuDiagnostics
	m.inputError = "some error"

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(model)

	if cmd != nil {
		t.Fatalf("esc in submenu should not quit")
	}
	if got.step != stepMenu || got.menuAction != menuNone {
		t.Fatalf("step/menuAction = %v/%v, want main menu", got.step, got.menuAction)
	}
	if got.inputError != "" {
		t.Fatalf("inputError should be cleared, got %q", got.inputError)
	}
}

func TestEscOnMainMenuQuits(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Fatal("esc on main menu should quit")
	}
}

func TestMenuActionWithoutProjectsShowsRetryableDetail(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	next, _ := m.handleMenuKey("1")
	got := next.(model)
	if got.step != stepActionDetail || !got.actionFailed {
		t.Fatalf("step/actionFailed = %v/%v, want failed detail", got.step, got.actionFailed)
	}
	if !strings.Contains(got.View(), "No local WhiteDNS projects") {
		t.Fatalf("view did not show no-projects message:\n%s", got.View())
	}
}

func TestInvalidDomainStaysOnDomainStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepDomain
	m.domainInput.SetValue("example.com/path")

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepDomain {
		t.Fatalf("step = %v, want stepDomain", got.step)
	}
	if got.inputError == "" {
		t.Fatal("expected inline validation error")
	}
	if !strings.Contains(got.View(), "bare DNS name") {
		t.Fatalf("view did not include inline error: %s", got.View())
	}
}

func TestInvalidIPStaysOnIPStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepIP
	m.ipInput.SetValue("2001:db8::1")

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepIP {
		t.Fatalf("step = %v, want stepIP", got.step)
	}
	if got.inputError == "" {
		t.Fatal("expected inline validation error")
	}
	if !strings.Contains(got.View(), "valid IPv4") {
		t.Fatalf("view did not include inline error: %s", got.View())
	}
}

func TestEmptyTokenStaysOnTokenStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepToken

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepToken {
		t.Fatalf("step = %v, want stepToken", got.step)
	}
	if got.inputError == "" {
		t.Fatal("expected inline validation error")
	}
	if !strings.Contains(got.View(), "token is required") {
		t.Fatalf("view did not include inline error: %s", got.View())
	}
}

func TestInvalidCloudflareTokenReturnsToTokenStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepApplying

	next, _ := m.Update(errorMsg{err: errors.New("verify Cloudflare token: Invalid API Token")})
	got := next.(model)

	if got.step != stepToken {
		t.Fatalf("step = %v, want stepToken", got.step)
	}
	if !strings.Contains(got.View(), "invalid or not authorized") {
		t.Fatalf("view did not include token error: %s", got.View())
	}
}

func TestInactiveZoneReturnsToDomainStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepApplying

	next, _ := m.Update(errorMsg{err: types.InactiveZoneError{
		Zone: types.Zone{
			Name:        "example.com",
			Status:      "pending",
			NameServers: []string{"a.ns.cloudflare.com", "b.ns.cloudflare.com"},
		},
	}})
	got := next.(model)

	if got.step != stepDomain {
		t.Fatalf("step = %v, want stepDomain", got.step)
	}
	if !strings.Contains(got.View(), "a.ns.cloudflare.com") {
		t.Fatalf("view did not include nameserver guidance: %s", got.View())
	}
}

func TestEmptyAccountIDStaysOnAccountStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepAccount
	m.accountInput.SetValue("")

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepAccount {
		t.Fatalf("step = %v, want stepAccount", got.step)
	}
	if !strings.Contains(got.View(), "account ID is required") {
		t.Fatalf("view did not include account error: %s", got.View())
	}
}

func TestAccountIDAdvancesToTokenStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepAccount
	m.accountInput.SetValue("account-id")

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepToken {
		t.Fatalf("step = %v, want stepToken", got.step)
	}
	if got.provisioner.AccountID != "account-id" {
		t.Fatalf("account ID = %q", got.provisioner.AccountID)
	}
}

func TestSavedCredentialsPrefillInputs(t *testing.T) {
	root := t.TempDir()
	if err := credentials.Save(root, credentials.CloudflareCredentials{
		AccountID: "saved-account",
		APIToken:  "saved-token",
	}); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	m := newModel(app.Provisioner{Root: root})

	if m.accountInput.Value() != "saved-account" {
		t.Fatalf("account input = %q", m.accountInput.Value())
	}
	if m.tokenInput.Value() != "saved-token" {
		t.Fatalf("token input = %q", m.tokenInput.Value())
	}
}

func TestSSHAuthFailureWithoutPasswordReturnsToKeyStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIChecking
	m.sshPassInput.SetValue("")

	next, _ := m.Update(errorMsg{err: errors.New("connect SSH root@178.105.177.76:22: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")})
	got := next.(model)

	if got.step != stepSSHKey {
		t.Fatalf("step = %v, want stepSSHKey", got.step)
	}
	if !strings.Contains(got.View(), "SSH authentication failed") {
		t.Fatalf("view did not include auth guidance: %s", got.View())
	}
}

func TestSSHAuthFailureWithPasswordReturnsToPasswordStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIChecking
	m.sshPassInput.SetValue("wrong-password")

	next, _ := m.Update(errorMsg{err: errors.New("connect SSH root@host:22: ssh: handshake failed: ssh: unable to authenticate, attempted methods [password], no supported methods remain")})
	got := next.(model)

	if got.step != stepSSHPassword {
		t.Fatalf("step = %v, want stepSSHPassword", got.step)
	}
	if !strings.Contains(got.View(), "Re-enter the SSH password") {
		t.Fatalf("view did not include password guidance: %s", got.View())
	}
}

func TestBlankSSHKeySkipsPassphraseStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepSSHKey
	m.sshKeyInput.SetValue("")

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepSSHPassword {
		t.Fatalf("step = %v, want stepSSHPassword", got.step)
	}
}

func TestExplicitSSHKeyShowsPassphraseStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepSSHKey
	m.sshKeyInput.SetValue("~/.ssh/id_ed25519")

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepSSHKeyPassphrase {
		t.Fatalf("step = %v, want stepSSHKeyPassphrase", got.step)
	}
	if !strings.Contains(got.View(), "SSH key passphrase") {
		t.Fatalf("view did not show passphrase screen: %s", got.View())
	}
}

func TestSSHKeyPassphraseStepAdvancesToPasswordStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepSSHKeyPassphrase
	m.sshKeyPassInput.SetValue("key-passphrase")

	next, _ := m.handleEnter()
	got := next.(model)

	if got.step != stepSSHPassword {
		t.Fatalf("step = %v, want stepSSHPassword", got.step)
	}
}

func TestSSHKeyPassphraseErrorReturnsToPassphraseStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIChecking

	next, _ := m.Update(errorMsg{err: errors.New("SSH key /tmp/id_ed25519 requires a passphrase: ssh: this private key is passphrase protected")})
	got := next.(model)

	if got.step != stepSSHKeyPassphrase {
		t.Fatalf("step = %v, want stepSSHKeyPassphrase", got.step)
	}
	if !strings.Contains(got.View(), "passphrase is required or incorrect") {
		t.Fatalf("view did not include passphrase guidance: %s", got.View())
	}
}

func TestSSHConnectionFailureReturnsToHostStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIChecking

	next, _ := m.Update(errorMsg{err: errors.New("connect SSH root@host:22: dial tcp: connection refused")})
	got := next.(model)

	if got.step != stepSSHHost {
		t.Fatalf("step = %v, want stepSSHHost", got.step)
	}
	if !strings.Contains(got.View(), "connection refused") {
		t.Fatalf("view did not include connection error: %s", got.View())
	}
}

func TestSSHKeyErrorReturnsToKeyStep(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIChecking

	next, _ := m.Update(errorMsg{err: errors.New("parse SSH key /tmp/key: ssh: no key found")})
	got := next.(model)

	if got.step != stepSSHKey {
		t.Fatalf("step = %v, want stepSSHKey", got.step)
	}
	if !strings.Contains(got.View(), "SSH key could not be used") {
		t.Fatalf("view did not include key guidance: %s", got.View())
	}
}

func TestXUIPanelLoginFailureReturnsToXUIConfirm(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIApplying
	m.sshPassInput.SetValue("correct-ssh-password")

	next, _ := m.Update(errorMsg{err: errors.New("validate 3x-ui panel login: login to 3x-ui panel: connection reset by peer")})
	got := next.(model)

	if got.step != stepXUIConfirm {
		t.Fatalf("step = %v, want stepXUIConfirm", got.step)
	}
	if strings.Contains(got.View(), "SSH password") {
		t.Fatalf("view should not ask for SSH password after panel login failure:\n%s", got.View())
	}
	if !strings.Contains(got.View(), "Press Y to retry apply") {
		t.Fatalf("view did not include retry guidance:\n%s", got.View())
	}
}

func TestXUIProgressMessageRendersApplyLog(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIApplying

	next, _ := m.Update(xuiProgressMsg("2026-06-05T00:00:00Z  Applying firewall rules."))
	got := next.(model)

	if got.step != stepXUIApplying {
		t.Fatalf("step = %v, want stepXUIApplying", got.step)
	}
	view := got.View()
	if !strings.Contains(view, "Log") || !strings.Contains(view, "Applying firewall rules") {
		t.Fatalf("view did not include progress log:\n%s", view)
	}
}

func TestXUIConfirmWithoutConflictsDoesNotSayReplace(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIConfirm
	m.xuiPlan = types.XUIPlan{
		Domain: "example.com",
		Protocols: []types.Protocol{
			{Enabled: true, Tag: "wdns-vless-ws", Hostname: "vpn.example.com", Port: 2083, Network: "tcp"},
		},
	}

	view := m.View()
	if !strings.Contains(view, "Apply 3x-ui changes?") {
		t.Fatalf("view did not include apply prompt: %s", view)
	}
	if strings.Contains(view, "replace listed conflicts") {
		t.Fatalf("view should not mention conflict replacement without conflicts: %s", view)
	}
}

func TestXUIConflictErrorPopulatesPlanAndReturnsToConfirm(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIApplying
	m.xuiPlan = types.XUIPlan{
		Domain: "example.com",
		Protocols: []types.Protocol{
			{Enabled: true, Tag: "wdns-vless-ws", Hostname: "vpn.example.com", Port: 2083, Network: "tcp"},
		},
	}

	next, _ := m.Update(errorMsg{err: xui.ConflictError{
		Conflicts: []types.XUIConflict{{Kind: "port", Name: "443", Detail: "existing inbound uses port", Action: "replace"}},
		Warnings:  []string{"warning"},
	}})
	got := next.(model)

	if got.step != stepXUIConfirm {
		t.Fatalf("step = %v, want stepXUIConfirm", got.step)
	}
	if len(got.xuiPlan.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v", got.xuiPlan.Conflicts)
	}
	view := got.View()
	if !strings.Contains(view, "Conflicts to replace") || !strings.Contains(view, "replace listed conflicts") {
		t.Fatalf("view did not show replacement confirmation: %s", view)
	}
}

func TestXUIDoneRendersLinksInPlainCodeBlock(t *testing.T) {
	m := newModel(app.Provisioner{Root: t.TempDir()})
	m.step = stepXUIDone
	m.xuiResult = xui.Result{
		ProjectDir: "/tmp/wdns/project",
		Links: types.ClientLinks{Clients: []types.ClientLink{
			{Name: "VLESS WS @whiteDNS", Link: "vless://uuid@vpn.example.com:443?type=ws#VLESS%20WS%20%40whiteDNS"},
			{Name: "Reality XHTTP @whiteDNS", Link: "vless://uuid@reality.example.com:2083?type=xhttp#Reality%20XHTTP%20%40whiteDNS"},
		}},
	}

	view := m.View()
	block := "```\n" +
		"# VLESS WS @whiteDNS\n" +
		"vless://uuid@vpn.example.com:443?type=ws#VLESS%20WS%20%40whiteDNS\n\n" +
		"# Reality XHTTP @whiteDNS\n" +
		"vless://uuid@reality.example.com:2083?type=xhttp#Reality%20XHTTP%20%40whiteDNS\n\n" +
		"Client links file:\n" +
		"/tmp/wdns/project/client-links.txt\n\n" +
		"Project directory:\n" +
		"/tmp/wdns/project\n" +
		"```"
	if !strings.Contains(view, block) {
		t.Fatalf("view did not include plain code block:\n%s", view)
	}
	if strings.Index(view, block) < strings.Index(view, "Client links are saved in client-links.txt") {
		t.Fatalf("code block should render after the status message:\n%s", view)
	}
	if strings.Contains(view, "QR codes") || strings.Contains(view, "\x1b[") {
		t.Fatalf("view should only include import strings, not QR output:\n%s", view)
	}
}
