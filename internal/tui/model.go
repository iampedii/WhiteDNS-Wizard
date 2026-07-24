package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/whitedns/wdns-wizard/internal/acme"
	"github.com/whitedns/wdns-wizard/internal/app"
	"github.com/whitedns/wdns-wizard/internal/planner"
	"github.com/whitedns/wdns-wizard/internal/xui"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

type step int

const (
	stepMenu step = iota
	stepWelcome
	stepAccount
	stepToken
	stepTokenChecking
	stepDomain
	stepIP
	stepConfirm
	stepApplying
	stepSSHHost
	stepSSHUser
	stepSSHKey
	stepSSHKeyPassphrase
	stepSSHPassword
	stepXUIChecking
	stepXUIConfirm
	stepXUIApplying
	stepXUIDone
	stepProjectSelect
	stepMenuDomain
	stepMenuIP
	stepActionConfirm
	stepMenuLoading
	stepActionDetail
	stepDone
	stepError
)

type menuAction int

const (
	menuNone menuAction = iota
	menuInfo
	menuDiagnostics
	menuRepair
	menuBackup
	menuRestore
	menuSupportBundle
	menuInbounds
	menuOutbounds
	menuClients
	menuDashboard
	menuChangeDomain
	menuReset
	menuDelete
)

type model struct {
	provisioner     app.Provisioner
	step            step
	accountInput    textinput.Model
	tokenInput      textinput.Model
	domainInput     textinput.Model
	ipInput         textinput.Model
	sshHostInput    textinput.Model
	sshUserInput    textinput.Model
	sshKeyInput     textinput.Model
	sshKeyPassInput textinput.Model
	sshPassInput    textinput.Model
	confirmInput    textinput.Model
	result          types.ProvisionResult
	xuiPlan         types.XUIPlan
	xuiResult       xui.Result
	projects        []xui.ProjectSummary
	selectedProject int
	menuAction      menuAction
	actionTitle     string
	actionBody      string
	actionFailed    bool
	xuiApplyLog     []string
	xuiProgress     <-chan tea.Msg
	err             error
	inputError      string
}

type resultMsg types.ProvisionResult
type xuiPlanMsg types.XUIPlan
type xuiResultMsg xui.Result
type actionResultMsg struct {
	title string
	body  string
}
type actionErrorMsg struct{ err error }
type tokenVerifiedMsg struct{}
type errorMsg struct{ err error }
type xuiProgressMsg string
type xuiApplyDoneMsg struct {
	result xui.Result
	err    error
}

var (
	titleStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	boxStyle         = lipgloss.NewStyle().Padding(1, 4).Width(96)
	hintStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	okStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	activeStepStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	doneStepStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	pendingStepStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

func Run(provisioner app.Provisioner) error {
	_, err := tea.NewProgram(newModel(provisioner), tea.WithAltScreen()).Run()
	return err
}

func appHeader() string {
	return titleStyle.Render("WhiteDNS") + "\n" + hintStyle.Render("@whitedns")
}

func newModel(provisioner app.Provisioner) model {
	saved, _ := provisioner.LoadCredentials()

	account := textinput.New()
	account.Placeholder = "Cloudflare account ID"
	account.CharLimit = 128
	account.Width = 58
	account.SetValue(saved.AccountID)
	if strings.TrimSpace(provisioner.AccountID) != "" {
		account.SetValue(strings.TrimSpace(provisioner.AccountID))
	}

	token := textinput.New()
	token.Placeholder = "Paste Cloudflare API token"
	token.CharLimit = 256
	token.Width = 58
	token.SetValue(saved.APIToken)

	domain := textinput.New()
	domain.Placeholder = "example.com"
	domain.CharLimit = 253
	domain.Width = 40

	ip := textinput.New()
	ip.Placeholder = "1.2.3.4"
	ip.CharLimit = 45
	ip.Width = 24

	sshHost := textinput.New()
	sshHost.Placeholder = "VPS SSH host or IP"
	sshHost.CharLimit = 253
	sshHost.Width = 40

	sshUser := textinput.New()
	sshUser.Placeholder = "root"
	sshUser.CharLimit = 64
	sshUser.Width = 24
	sshUser.SetValue("root")

	sshKey := textinput.New()
	sshKey.Placeholder = "~/.ssh/id_ed25519 (optional)"
	sshKey.CharLimit = 512
	sshKey.Width = 54

	sshKeyPass := textinput.New()
	sshKeyPass.Placeholder = "SSH key passphrase (optional)"
	sshKeyPass.CharLimit = 256
	sshKeyPass.Width = 40
	sshKeyPass.EchoMode = textinput.EchoPassword
	sshKeyPass.EchoCharacter = '*'

	sshPass := textinput.New()
	sshPass.Placeholder = "SSH password (optional)"
	sshPass.CharLimit = 256
	sshPass.Width = 40
	sshPass.EchoMode = textinput.EchoPassword
	sshPass.EchoCharacter = '*'

	confirm := textinput.New()
	confirm.Placeholder = "Type confirmation"
	confirm.CharLimit = 16
	confirm.Width = 24

	account.Focus()
	return model{
		provisioner:     provisioner,
		step:            stepMenu,
		accountInput:    account,
		tokenInput:      token,
		domainInput:     domain,
		ipInput:         ip,
		sshHostInput:    sshHost,
		sshUserInput:    sshUser,
		sshKeyInput:     sshKey,
		sshKeyPassInput: sshKeyPass,
		sshPassInput:    sshPass,
		confirmInput:    confirm,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.escReturnsToMenu() {
				return m.resetToMenu(), nil
			}
			return m, tea.Quit
		case "b":
			if m.step == stepProjectSelect || m.step == stepActionDetail {
				return m.resetToMenu(), nil
			}
		case "enter":
			return m.handleEnter()
		case "q":
			if m.step == stepMenu || m.step == stepProjectSelect || m.step == stepActionDetail || m.step == stepDone || m.step == stepError || m.step == stepConfirm || m.step == stepXUIConfirm || m.step == stepXUIDone {
				return m, tea.Quit
			}
		case "y", "Y":
			if m.step == stepConfirm {
				m.step = stepApplying
				return m, m.applyCmd()
			}
			if m.step == stepXUIConfirm {
				return m.startXUIApply()
			}
		case "n", "N":
			if m.step == stepConfirm || m.step == stepXUIConfirm {
				return m, tea.Quit
			}
		}
		if m.step == stepMenu {
			return m.handleMenuKey(msg.String())
		}
		if m.step == stepProjectSelect {
			return m.handleProjectKey(msg.String())
		}
	case resultMsg:
		m.result = types.ProvisionResult(msg)
		m.step = stepSSHHost
		m.sshHostInput.SetValue(m.ipInput.Value())
		m.sshHostInput.Focus()
		m.ipInput.Blur()
		return m, nil
	case xuiPlanMsg:
		m.xuiPlan = types.XUIPlan(msg)
		m.step = stepXUIConfirm
		return m, nil
	case xuiResultMsg:
		m.xuiResult = xui.Result(msg)
		m.step = stepXUIDone
		return m, nil
	case xuiProgressMsg:
		m.xuiApplyLog = append(m.xuiApplyLog, string(msg))
		if len(m.xuiApplyLog) > 200 {
			m.xuiApplyLog = m.xuiApplyLog[len(m.xuiApplyLog)-200:]
		}
		if m.xuiProgress != nil {
			return m, waitXUIProgressCmd(m.xuiProgress)
		}
		return m, nil
	case xuiApplyDoneMsg:
		m.xuiProgress = nil
		if msg.err != nil {
			return m.handleProvisionError(msg.err), nil
		}
		m.xuiResult = msg.result
		m.step = stepXUIDone
		return m, nil
	case actionResultMsg:
		m.actionTitle = msg.title
		m.actionBody = msg.body
		m.actionFailed = false
		m.step = stepActionDetail
		return m, nil
	case actionErrorMsg:
		return m.handleMenuError(msg.err), nil
	case tokenVerifiedMsg:
		m.inputError = ""
		m.step = stepDomain
		m.tokenInput.Blur()
		m.domainInput.Focus()
		return m, nil
	case errorMsg:
		return m.handleProvisionError(msg.err), nil
	}

	var cmd tea.Cmd
	switch m.step {
	case stepAccount:
		m.accountInput, cmd = m.accountInput.Update(msg)
	case stepToken:
		m.tokenInput, cmd = m.tokenInput.Update(msg)
	case stepDomain:
		m.domainInput, cmd = m.domainInput.Update(msg)
	case stepIP:
		m.ipInput, cmd = m.ipInput.Update(msg)
	case stepMenuDomain:
		m.domainInput, cmd = m.domainInput.Update(msg)
	case stepMenuIP:
		m.ipInput, cmd = m.ipInput.Update(msg)
	case stepSSHHost:
		m.sshHostInput, cmd = m.sshHostInput.Update(msg)
	case stepSSHUser:
		m.sshUserInput, cmd = m.sshUserInput.Update(msg)
	case stepSSHKey:
		m.sshKeyInput, cmd = m.sshKeyInput.Update(msg)
	case stepSSHKeyPassphrase:
		m.sshKeyPassInput, cmd = m.sshKeyPassInput.Update(msg)
	case stepSSHPassword:
		m.sshPassInput, cmd = m.sshPassInput.Update(msg)
	case stepActionConfirm:
		m.confirmInput, cmd = m.confirmInput.Update(msg)
	}
	if _, ok := msg.(tea.KeyMsg); ok && (m.step == stepAccount || m.step == stepToken || m.step == stepDomain || m.step == stepIP || m.step == stepMenuDomain || m.step == stepMenuIP || m.step == stepSSHHost || m.step == stepSSHUser || m.step == stepSSHKey || m.step == stepSSHKeyPassphrase || m.step == stepSSHPassword || m.step == stepActionConfirm) {
		m.inputError = ""
	}
	return m, cmd
}

func (m model) handleEnter() (tea.Model, tea.Cmd) {
	switch m.step {
	case stepMenu:
		return m, nil
	case stepProjectSelect:
		return m.selectProject()
	case stepWelcome:
		m.step = stepAccount
		m.accountInput.Focus()
	case stepAccount:
		if strings.TrimSpace(m.accountInput.Value()) == "" {
			m.inputError = "Cloudflare account ID is required."
			return m, nil
		}
		m.inputError = ""
		m.provisioner.AccountID = strings.TrimSpace(m.accountInput.Value())
		m.step = stepToken
		m.accountInput.Blur()
		m.tokenInput.Focus()
	case stepToken:
		if strings.TrimSpace(m.tokenInput.Value()) == "" {
			m.inputError = "Cloudflare API token is required."
			return m, nil
		}
		m.inputError = ""
		m.step = stepTokenChecking
		m.tokenInput.Blur()
		return m, m.verifyTokenCmd()
	case stepDomain:
		if _, err := planner.NormalizeDomain(m.domainInput.Value()); err != nil {
			m.inputError = err.Error()
			m.domainInput.Focus()
			return m, nil
		}
		m.inputError = ""
		m.step = stepIP
		m.domainInput.Blur()
		m.ipInput.Focus()
	case stepIP:
		if _, err := planner.ValidateIPv4(m.ipInput.Value()); err != nil {
			m.inputError = err.Error()
			m.ipInput.Focus()
			return m, nil
		}
		m.inputError = ""
		m.step = stepConfirm
		m.ipInput.Blur()
	case stepMenuDomain:
		if _, err := planner.NormalizeDomain(m.domainInput.Value()); err != nil {
			m.inputError = err.Error()
			m.domainInput.Focus()
			return m, nil
		}
		m.inputError = ""
		m.step = stepMenuIP
		m.domainInput.Blur()
		m.ipInput.Focus()
	case stepMenuIP:
		if _, err := planner.ValidateIPv4(m.ipInput.Value()); err != nil {
			m.inputError = err.Error()
			m.ipInput.Focus()
			return m, nil
		}
		m.inputError = ""
		m.ipInput.Blur()
		m.prefillSSHFromSelectedProject()
		m.step = stepSSHHost
		m.sshHostInput.Focus()
	case stepConfirm:
		m.step = stepApplying
		return m, m.applyCmd()
	case stepSSHHost:
		if strings.TrimSpace(m.sshHostInput.Value()) == "" {
			m.inputError = "SSH host is required."
			m.sshHostInput.Focus()
			return m, nil
		}
		m.inputError = ""
		m.step = stepSSHUser
		m.sshHostInput.Blur()
		m.sshUserInput.Focus()
	case stepSSHUser:
		if strings.TrimSpace(m.sshUserInput.Value()) == "" {
			m.inputError = "SSH user is required."
			m.sshUserInput.Focus()
			return m, nil
		}
		m.inputError = ""
		m.step = stepSSHKey
		m.sshUserInput.Blur()
		m.sshKeyInput.Focus()
	case stepSSHKey:
		m.inputError = ""
		m.sshKeyInput.Blur()
		if strings.TrimSpace(m.sshKeyInput.Value()) != "" {
			m.step = stepSSHKeyPassphrase
			m.sshKeyPassInput.Focus()
			return m, nil
		}
		m.step = stepSSHPassword
		m.sshPassInput.Focus()
	case stepSSHKeyPassphrase:
		m.inputError = ""
		m.step = stepSSHPassword
		m.sshKeyPassInput.Blur()
		m.sshPassInput.Focus()
	case stepSSHPassword:
		m.inputError = ""
		m.sshPassInput.Blur()
		if m.menuAction != menuNone {
			m.step = stepMenuLoading
			return m, m.menuActionCmd()
		}
		m.step = stepXUIChecking
		return m, m.xuiPlanCmd()
	case stepActionConfirm:
		want := confirmationWord(m.menuAction)
		if strings.TrimSpace(m.confirmInput.Value()) != want {
			m.inputError = "Type " + want + " to continue."
			m.confirmInput.Focus()
			return m, nil
		}
		m.inputError = ""
		m.confirmInput.Blur()
		m.prefillSSHFromSelectedProject()
		m.step = stepSSHHost
		m.sshHostInput.Focus()
	case stepActionDetail:
		if m.actionFailed && m.menuAction != menuNone {
			if len(m.projects) == 0 {
				return m.startProjectAction(m.menuAction)
			}
			m.step = stepMenuLoading
			return m, m.menuActionCmd()
		}
		return m.resetToMenu(), nil
	case stepXUIConfirm:
		return m.startXUIApply()
	case stepXUIDone:
		return m, tea.Quit
	case stepDone, stepError:
		return m, tea.Quit
	}
	return m, nil
}

func (m model) View() string {
	if m.step == stepXUIDone {
		return m.xuiDoneView()
	}

	var body string
	switch m.step {
	case stepMenu:
		body = appHeader() + "\n" +
			hintStyle.Render("Interactive provisioning") + "\n\n" +
			"WhiteDNS menu\n\n" +
			"0) Init setup\n" +
			"1) Current setup info\n" +
			"2) Diagnostics\n" +
			"3) Repair installation\n" +
			"4) Backup installation\n" +
			"5) Restore latest backup\n" +
			"6) Support bundle\n" +
			"7) Get list of inbounds\n" +
			"8) Get list of outbounds\n" +
			"9) Get list of clients (10 only)\n" +
			"d) Dashboard credentials and login info\n" +
			"c) Change Cloudflare domain\n" +
			"r) Reset installation\n" +
			"x) Delete installation\n\n" +
			m.inlineError() +
			hintStyle.Render("Press a shortcut key. Press q or esc to exit.")
	case stepWelcome:
		body = titleStyle.Render("Start setup") + "\n\n" +
			"Create a Cloudflare-ready VPN provisioning project.\n\n" +
			"This wizard will:\n" +
			"- verify your Cloudflare token\n" +
			"- detect your Cloudflare zone\n" +
			"- create/update DNS records\n" +
			"- set SSL mode to strict\n" +
			"- create an Origin CA certificate\n" +
			"- export local plans and encrypted secrets\n\n" +
			hintStyle.Render("Press Enter to start.")
	case stepAccount:
		body = titleStyle.Render("Cloudflare account ID") + "\n\n" +
			m.accountInput.View() + "\n\n" +
			m.inlineError() +
			"Enter your own Cloudflare account ID. This is not hard-coded.\n" +
			"WhiteDNS uses it for:\n" +
			"GET /client/v4/accounts/<account-id>/tokens/verify\n\n" +
			hintStyle.Render("This is saved after token verification. Press Enter to continue.")
	case stepToken:
		body = titleStyle.Render("Cloudflare API token") + "\n\n" +
			m.tokenInput.View() + "\n\n" +
			m.inlineError() +
			"Create the token in Cloudflare:\n" +
			"1. Manage Account > Account API Tokens > Create Token\n" +
			"2. Choose the Edit zone DNS template\n" +
			"3. Scope it to the owning Cloudflare zone when possible\n" +
			"4. Keep DNS: Read + Edit\n" +
			"5. Add:\n" +
			"   - DNS & Zones / Zone: Read\n" +
			"   - DNS & Zones / Zone Settings: Edit\n" +
			"   - Cache & Performance / Zone SSL & Certificates: Edit\n\n" +
			"Token validation endpoint:\n" +
			"GET /client/v4/accounts/" + strings.TrimSpace(m.accountInput.Value()) + "/tokens/verify\n\n" +
			"Cloudflare API docs may call Edit permissions Write.\n\n" +
			hintStyle.Render("Press Enter to continue.")
	case stepTokenChecking:
		body = titleStyle.Render("Validating token") + "\n\n" +
			"Checking Cloudflare account token...\n\n" +
			hintStyle.Render("This uses the account token verify endpoint.")
	case stepDomain:
		body = titleStyle.Render("Domain") + "\n\n" +
			"Enter the domain to provision.\n\n" +
			m.domainInput.View() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("Examples: example.com or team.example.com")
	case stepIP:
		body = titleStyle.Render("VPS IPv4") + "\n\n" +
			"Enter the server IPv4 address for DNS records.\n\n" +
			m.ipInput.View() + "\n\n" +
			m.inlineError()
	case stepProjectSelect:
		body = titleStyle.Render(menuActionTitle(m.menuAction)) + "\n\n" +
			"Select a project.\n\n" +
			m.projectListView() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("Use up/down and Enter, or press a number. Press b or esc to go back.")
	case stepMenuDomain:
		body = titleStyle.Render("Change Cloudflare domain") + "\n\n" +
			"Enter the new domain to provision.\n\n" +
			m.domainInput.View() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("Subdomains can use their parent Cloudflare zone. Existing client IDs and passwords will be reused where possible.")
	case stepMenuIP:
		body = titleStyle.Render("VPS IPv4") + "\n\n" +
			"Enter the server IPv4 address for the new domain.\n\n" +
			m.ipInput.View() + "\n\n" +
			m.inlineError()
	case stepConfirm:
		domain, _ := planner.NormalizeDomain(m.domainInput.Value())
		ip, _ := planner.ValidateIPv4(m.ipInput.Value())
		plan := planner.GenerateDNSPlan(domain, ip)
		body = titleStyle.Render("DNS plan") + "\n\n"
		for _, record := range plan.Records {
			mode := "DNS-only"
			if record.Proxied {
				mode = "Proxied"
			}
			body += fmt.Sprintf("%-24s %-2s %-15s %s\n", record.Name, record.Type, record.Content, mode)
		}
		body += "\n" + warnStyle.Render("Apply Cloudflare changes and write local project files? [Y/n]")
	case stepApplying:
		body = titleStyle.Render("Applying") + "\n\n" +
			"Applying Cloudflare DNS, SSL, Origin CA, and local output...\n\n" +
			hintStyle.Render("This can take a moment.")
	case stepSSHHost:
		if m.menuAction != menuNone {
			body = titleStyle.Render(menuActionTitle(m.menuAction)) + "\n\n" +
				"Enter the VPS SSH host for this action.\n\n"
		} else {
			body = titleStyle.Render("Cloudflare complete") + "\n\n" +
				okStyle.Render("DNS, SSL mode, Origin CA, and local plans are ready.") + "\n\n" +
				"Enter the VPS SSH host. The wizard will run locally and manage the server over SSH.\n\n"
		}
		body +=
			m.sshHostInput.View() + "\n\n" +
				m.inlineError() +
				hintStyle.Render("Press Enter to continue.")
	case stepSSHUser:
		body = titleStyle.Render("SSH user") + "\n\n" +
			m.sshUserInput.View() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("Default: root")
	case stepSSHKey:
		body = titleStyle.Render("SSH key") + "\n\n" +
			"Enter a private key path, or leave blank to use ssh-agent/default keys.\n\n" +
			m.sshKeyInput.View() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("Press Enter to continue.")
	case stepSSHKeyPassphrase:
		body = titleStyle.Render("SSH key passphrase") + "\n\n" +
			"Optional. Leave blank only if the selected key is not encrypted.\n\n" +
			m.sshKeyPassInput.View() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("This passphrase is not saved.")
	case stepSSHPassword:
		body = titleStyle.Render("SSH password") + "\n\n" +
			"Optional. Leave blank to use key or ssh-agent authentication only.\n\n" +
			m.sshPassInput.View() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("This password is not saved.")
	case stepXUIChecking:
		body = titleStyle.Render("Checking VPS") + "\n\n" +
			"Connecting over SSH and inspecting Docker / 3x-ui status...\n\n" +
			hintStyle.Render("This can take a moment.")
	case stepXUIConfirm:
		body = titleStyle.Render("3x-ui plan") + "\n\n"
		if m.xuiPlan.InstallRequired {
			body += "Install: Docker 3x-ui with PostgreSQL\n"
		} else {
			body += "Install: existing Docker 3x-ui detected\n"
		}
		body += "\nProtocols:\n"
		for _, proto := range m.xuiPlan.Protocols {
			if !proto.Enabled {
				continue
			}
			network := proto.Network
			if network == "" {
				network = "tcp"
			}
			body += fmt.Sprintf("- %-24s %s:%d/%s\n", xui.DisplayNameForTag(proto.Tag), proto.Hostname, proto.Port, network)
		}
		if len(m.xuiPlan.Warnings) > 0 {
			body += "\n" + warnStyle.Render("Warnings:") + "\n"
			for _, warning := range m.xuiPlan.Warnings {
				body += "- " + warning + "\n"
			}
		}
		if len(m.xuiPlan.Conflicts) > 0 {
			body += "\n" + warnStyle.Render("Conflicts to replace:") + "\n"
			for _, conflict := range m.xuiPlan.Conflicts {
				body += fmt.Sprintf("- %-8s %-18s %s\n", conflict.Kind, conflict.Name, conflict.Detail)
			}
			body += "\n" + m.inlineError() + warnStyle.Render("Apply 3x-ui changes and replace listed conflicts? [Y/n]")
		} else {
			body += "\n" + m.inlineError() + warnStyle.Render("Apply 3x-ui changes? [Y/n]")
		}
	case stepXUIApplying:
		body = titleStyle.Render("Applying 3x-ui") + "\n\n" +
			"Installing/checking Docker 3x-ui, issuing public certs, uploading certs, and applying inbounds/outbounds...\n\n" +
			hintStyle.Render("This can take a while, especially during ACME DNS validation.") +
			m.xuiApplyLogView()
	case stepActionConfirm:
		word := confirmationWord(m.menuAction)
		description := confirmationDescription(m.menuAction)
		body = titleStyle.Render(menuActionTitle(m.menuAction)) + "\n\n" +
			warnStyle.Render(description) + "\n\n" +
			"Project: " + m.selectedDomain() + "\n\n" +
			"Type " + word + " to continue.\n\n" +
			m.confirmInput.View() + "\n\n" +
			m.inlineError() +
			hintStyle.Render("Press b or esc to go back.")
	case stepMenuLoading:
		body = titleStyle.Render(menuActionTitle(m.menuAction)) + "\n\n" +
			"Running action...\n\n" +
			hintStyle.Render("This can take a moment.")
	case stepActionDetail:
		status := okStyle.Render("Complete")
		hint := "Press Enter, b, or esc to return to menu. Press q to exit."
		if m.actionFailed {
			status = warnStyle.Render("Error")
			hint = "Press Enter to retry, b or esc to return to menu, or q to exit."
		}
		body = titleStyle.Render(m.actionTitle) + "\n\n" +
			status + "\n\n" +
			m.actionBody + "\n\n" +
			hintStyle.Render(hint)
	case stepDone:
		body = titleStyle.Render("Complete") + "\n\n" +
			okStyle.Render("Cloudflare setup complete.") + "\n\n"
		for _, result := range m.result.DNSResults {
			body += fmt.Sprintf("%-10s %s\n", result.Status, result.Record.Name)
		}
		body += "\nProject directory:\n" + m.result.ProjectDir + "\n\n" + hintStyle.Render("Press Enter to exit.")
	case stepError:
		body = titleStyle.Render("Error") + "\n\n" +
			warnStyle.Render(m.err.Error()) + "\n\n" +
			hintStyle.Render("Press Enter to exit.")
	}
	return m.renderPage(body)
}

func (m model) xuiDoneView() string {
	body := titleStyle.Render("Complete") + "\n\n" +
		okStyle.Render("Cloudflare and 3x-ui setup complete.") + "\n\n" +
		"Client links are saved in client-links.txt and shown below.\n\n" +
		hintStyle.Render("Press Enter to exit.")
	return m.renderPage(body) + "\n\n" + clientLinksCodeBlock(m.xuiResult) + "\n"
}

func (m model) renderPage(body string) string {
	if m.showInitSteps() {
		body = appHeader() + "\n" +
			m.initStepsView() + "\n\n" +
			body
	}
	return "\n" + boxStyle.Render(body) + "\n"
}

func clientLinksCodeBlock(result xui.Result) string {
	var b strings.Builder
	b.WriteString("```\n")
	for _, client := range result.Links.Clients {
		b.WriteString("# ")
		b.WriteString(client.Name)
		b.WriteByte('\n')
		b.WriteString(client.Link)
		b.WriteString("\n\n")
	}
	b.WriteString("Client links file:\n")
	b.WriteString(result.ProjectDir)
	b.WriteString("/client-links.txt\n\n")
	if strings.TrimSpace(result.LogPath) != "" {
		b.WriteString("Log file:\n")
		b.WriteString(result.LogPath)
		b.WriteString("\n\n")
	}
	b.WriteString("Project directory:\n")
	b.WriteString(result.ProjectDir)
	b.WriteString("\n```")
	return b.String()
}

func (m model) handleMenuKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "0":
		m.menuAction = menuNone
		m.inputError = ""
		m.step = stepWelcome
		return m, nil
	case "1":
		return m.startProjectAction(menuInfo)
	case "2":
		return m.startProjectAction(menuDiagnostics)
	case "3":
		return m.startProjectAction(menuRepair)
	case "4":
		return m.startProjectAction(menuBackup)
	case "5":
		return m.startProjectAction(menuRestore)
	case "6":
		return m.startProjectAction(menuSupportBundle)
	case "7":
		return m.startProjectAction(menuInbounds)
	case "8":
		return m.startProjectAction(menuOutbounds)
	case "9":
		return m.startProjectAction(menuClients)
	case "d", "D":
		return m.startProjectAction(menuDashboard)
	case "c", "C":
		return m.startProjectAction(menuChangeDomain)
	case "r", "R":
		return m.startProjectAction(menuReset)
	case "x", "X":
		return m.startProjectAction(menuDelete)
	default:
		return m, nil
	}
}

func (m model) startProjectAction(action menuAction) (tea.Model, tea.Cmd) {
	projects, err := xui.ProjectSummaries(m.provisioner.Root)
	if err != nil {
		m.inputError = err.Error()
		return m, nil
	}
	m.menuAction = action
	m.projects = projects
	m.selectedProject = 0
	m.actionTitle = menuActionTitle(action)
	m.actionBody = ""
	m.actionFailed = false
	if len(projects) == 0 {
		m.step = stepActionDetail
		m.actionFailed = true
		m.actionBody = "No local WhiteDNS projects were found. Run option 0 first."
		return m, nil
	}
	m.step = stepProjectSelect
	return m, nil
}

func (m model) handleProjectKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.selectedProject > 0 {
			m.selectedProject--
		}
		return m, nil
	case "down", "j":
		if m.selectedProject < len(m.projects)-1 {
			m.selectedProject++
		}
		return m, nil
	case "enter":
		return m.selectProject()
	}
	if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
		index := int(key[0] - '1')
		if index >= 0 && index < len(m.projects) {
			m.selectedProject = index
			return m.selectProject()
		}
	}
	return m, nil
}

func (m model) selectProject() (tea.Model, tea.Cmd) {
	m.inputError = ""
	m.domainInput.SetValue(m.selectedDomain())
	if len(m.projects) > 0 {
		project := m.projects[m.selectedProject]
		m.ipInput.SetValue(project.VPSIP)
		m.sshHostInput.SetValue(firstNonEmpty(project.SSHHost, project.VPSIP))
	}
	switch m.menuAction {
	case menuInfo, menuDashboard:
		m.step = stepMenuLoading
		return m, m.menuActionCmd()
	case menuChangeDomain:
		m.domainInput.SetValue("")
		m.domainInput.Focus()
		m.step = stepMenuDomain
		return m, nil
	case menuRepair, menuRestore, menuReset, menuDelete:
		m.confirmInput.SetValue("")
		m.confirmInput.Focus()
		m.step = stepActionConfirm
		return m, nil
	default:
		m.prefillSSHFromSelectedProject()
		m.step = stepSSHHost
		m.sshHostInput.Focus()
		return m, nil
	}
}

func (m model) resetToMenu() model {
	m.step = stepMenu
	m.menuAction = menuNone
	m.inputError = ""
	m.actionTitle = ""
	m.actionBody = ""
	m.actionFailed = false
	m.confirmInput.Blur()
	m.domainInput.Blur()
	m.ipInput.Blur()
	m.sshHostInput.Blur()
	m.sshUserInput.Blur()
	m.sshKeyInput.Blur()
	m.sshKeyPassInput.Blur()
	m.sshPassInput.Blur()
	return m
}

func (m *model) prefillSSHFromSelectedProject() {
	if len(m.projects) > 0 && m.selectedProject >= 0 && m.selectedProject < len(m.projects) {
		project := m.projects[m.selectedProject]
		if strings.TrimSpace(m.sshHostInput.Value()) == "" {
			m.sshHostInput.SetValue(firstNonEmpty(project.SSHHost, project.VPSIP))
		}
	}
	if strings.TrimSpace(m.sshUserInput.Value()) == "" {
		m.sshUserInput.SetValue("root")
	}
}

func (m model) selectedDomain() string {
	if len(m.projects) == 0 || m.selectedProject < 0 || m.selectedProject >= len(m.projects) {
		return ""
	}
	return m.projects[m.selectedProject].Domain
}

func (m model) projectListView() string {
	var b strings.Builder
	for i, project := range m.projects {
		cursor := " "
		if i == m.selectedProject {
			cursor = ">"
		}
		last := "never"
		if !project.LastApplied.IsZero() {
			last = project.LastApplied.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(&b, "%s %d) %-28s ip=%-15s ssh=%-15s last=%s\n", cursor, i+1, project.Domain, project.VPSIP, project.SSHHost, last)
	}
	return strings.TrimRight(b.String(), "\n")
}

func menuActionTitle(action menuAction) string {
	switch action {
	case menuInfo:
		return "Current setup info"
	case menuDiagnostics:
		return "Diagnostics"
	case menuRepair:
		return "Repair installation"
	case menuBackup:
		return "Backup installation"
	case menuRestore:
		return "Restore latest backup"
	case menuSupportBundle:
		return "Support bundle"
	case menuInbounds:
		return "3x-ui inbounds"
	case menuOutbounds:
		return "3x-ui outbounds"
	case menuClients:
		return "3x-ui clients"
	case menuDashboard:
		return "Dashboard credentials"
	case menuChangeDomain:
		return "Change Cloudflare domain"
	case menuReset:
		return "Reset installation"
	case menuDelete:
		return "Delete installation"
	default:
		return "WhiteDNS"
	}
}

func confirmationWord(action menuAction) string {
	switch action {
	case menuRepair:
		return "REPAIR"
	case menuRestore:
		return "RESTORE"
	case menuDelete:
		return "DELETE"
	default:
		return "RESET"
	}
}

func confirmationDescription(action menuAction) string {
	switch action {
	case menuRepair:
		return "Repair will reapply only WhiteDNS-managed 3x-ui resources and will not change Cloudflare."
	case menuRestore:
		return "Restore will replace the managed remote stack from the latest backup and restore local project files."
	case menuDelete:
		return "Delete removes WhiteDNS-managed remote entries, stack, Docker images, and build cache. Local project files are kept."
	default:
		return "Reset will repair/reapply the managed WhiteDNS installation and preserve local secrets."
	}
}

func (m model) showInitSteps() bool {
	if m.menuAction != menuNone {
		return false
	}
	switch m.step {
	case stepWelcome, stepAccount, stepToken, stepTokenChecking, stepDomain, stepIP, stepConfirm, stepApplying, stepSSHHost, stepSSHUser, stepSSHKey, stepSSHKeyPassphrase, stepSSHPassword, stepXUIChecking, stepXUIConfirm, stepXUIApplying, stepXUIDone, stepDone, stepError:
		return true
	default:
		return false
	}
}

func (m model) escReturnsToMenu() bool {
	switch m.step {
	case stepProjectSelect, stepActionConfirm, stepMenuLoading, stepActionDetail, stepMenuDomain, stepMenuIP:
		return true
	case stepSSHHost, stepSSHUser, stepSSHKey, stepSSHKeyPassphrase, stepSSHPassword:
		return m.menuAction != menuNone
	default:
		return false
	}
}

func (m model) initStepsView() string {
	steps := []string{"Cloudflare", "Domain", "DNS", "SSH", "3x-ui", "Output"}
	current := m.initStepIndex()
	parts := make([]string, 0, len(steps))
	for i, label := range steps {
		text := fmt.Sprintf("%d %s", i+1, label)
		switch {
		case i < current:
			parts = append(parts, doneStepStyle.Render(text))
		case i == current:
			parts = append(parts, activeStepStyle.Render(text))
		default:
			parts = append(parts, pendingStepStyle.Render(text))
		}
	}
	return hintStyle.Render("Setup: ") + strings.Join(parts, pendingStepStyle.Render("  /  "))
}

func (m model) initStepIndex() int {
	switch m.step {
	case stepWelcome, stepAccount, stepToken, stepTokenChecking:
		return 0
	case stepDomain, stepIP:
		return 1
	case stepConfirm, stepApplying, stepDone:
		return 2
	case stepSSHHost, stepSSHUser, stepSSHKey, stepSSHKeyPassphrase, stepSSHPassword, stepXUIChecking:
		return 3
	case stepXUIConfirm, stepXUIApplying:
		return 4
	case stepXUIDone:
		return 5
	default:
		return 0
	}
}

func (m model) inlineError() string {
	if m.inputError == "" {
		return ""
	}
	return warnStyle.Render(m.inputError) + "\n\n"
}

func (m model) xuiApplyLogView() string {
	if len(m.xuiApplyLog) == 0 {
		return "\n\n" + titleStyle.Render("Log") + "\n" + hintStyle.Render("Waiting for first progress event...")
	}
	start := 0
	if len(m.xuiApplyLog) > 8 {
		start = len(m.xuiApplyLog) - 8
	}
	var b strings.Builder
	b.WriteString("\n\n")
	b.WriteString(titleStyle.Render("Log"))
	b.WriteByte('\n')
	for _, line := range m.xuiApplyLog[start:] {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m model) handleProvisionError(err error) model {
	m.err = nil
	m.inputError = ""
	m.accountInput.Blur()
	m.tokenInput.Blur()
	m.domainInput.Blur()
	m.ipInput.Blur()
	m.sshHostInput.Blur()
	m.sshUserInput.Blur()
	m.sshKeyInput.Blur()
	m.sshKeyPassInput.Blur()
	m.sshPassInput.Blur()

	var inactive types.InactiveZoneError
	if errors.As(err, &inactive) {
		m.step = stepDomain
		m.domainInput.Focus()
		if len(inactive.Zone.NameServers) > 0 {
			m.inputError = "Zone is not active yet. Update the domain nameserver settings at the registrar/domain provider to: " + strings.Join(inactive.Zone.NameServers, ", ") + ". This is not a DNS record in the Cloudflare DNS records table."
		} else {
			m.inputError = "Zone is not active yet. Update nameservers at the registrar/domain provider, then try again. This is not a DNS record in the Cloudflare DNS records table."
		}
		return m
	}
	var conflict xui.ConflictError
	if errors.As(err, &conflict) {
		m.xuiPlan.Conflicts = conflict.Conflicts
		m.xuiPlan.Warnings = appendWarnings(m.xuiPlan.Warnings, conflict.Warnings)
		m.step = stepXUIConfirm
		m.inputError = "3x-ui conflicts were found after the managed stack became available. Review the list before confirming replacement."
		return m
	}
	var acmeFallback xui.ACMEFallbackError
	if errors.As(err, &acmeFallback) {
		m.step = stepXUIConfirm
		m.inputError = acmeFallback.Error()
		return m
	}
	var acmePreflight acme.PreflightError
	if errors.As(err, &acmePreflight) {
		if acmePreflight.Kind == acme.PreflightKindToken {
			m.step = stepToken
			m.tokenInput.Focus()
			m.inputError = "Cloudflare API token cannot access this zone for ACME DNS-01. Check token scope, paste a valid token, and try again."
			return m
		}
		m.step = stepDomain
		m.domainInput.Focus()
		m.inputError = acmePreflight.Error()
		return m
	}

	message := err.Error()
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "verify cloudflare token") ||
		strings.Contains(lower, "invalid api token") ||
		strings.Contains(lower, "token status"):
		m.step = stepToken
		m.tokenInput.Focus()
		m.inputError = "Cloudflare API token is invalid or not authorized. Paste a valid token and try again."
	case strings.Contains(lower, "cloudflare account id"):
		m.step = stepAccount
		m.accountInput.Focus()
		m.inputError = "Cloudflare account ID is required."
	case strings.Contains(lower, "zone") && strings.Contains(lower, "not found"):
		m.step = stepDomain
		m.domainInput.Focus()
		m.inputError = "Cloudflare zone was not found. Check the domain or token zone scope, then try again."
	case strings.Contains(lower, "vps ip") || strings.Contains(lower, "ipv4"):
		m.step = stepIP
		m.ipInput.Focus()
		m.inputError = message
	case isSSHKeyPassphraseError(lower):
		m.step = stepSSHKeyPassphrase
		m.sshKeyPassInput.Focus()
		m.inputError = "SSH key passphrase is required or incorrect. Re-enter the key passphrase, or leave the key path blank to use password auth."
	case isSSHKeyError(lower):
		m.step = stepSSHKey
		m.sshKeyInput.Focus()
		m.inputError = "SSH key could not be used. Enter a valid private key path, or leave blank to try password auth."
	case isSSHAuthError(lower):
		if strings.TrimSpace(m.sshPassInput.Value()) == "" {
			m.step = stepSSHKey
			m.sshKeyInput.Focus()
			m.inputError = "SSH authentication failed. Enter a valid private key path, or press Enter to try a password."
		} else {
			m.step = stepSSHPassword
			m.sshPassInput.Focus()
			m.inputError = "SSH authentication failed. Re-enter the SSH password or check that root login is allowed."
		}
	case isSSHConnectError(lower):
		m.step = stepSSHHost
		m.sshHostInput.Focus()
		m.inputError = message
	case strings.Contains(lower, "3x-ui panel login") || strings.Contains(lower, "login to 3x-ui"):
		m.step = stepXUIConfirm
		m.inputError = "3x-ui is installed, but the panel login is not ready or credentials were just reset. Press Y to retry apply."
	case strings.Contains(lower, "conflicts require confirmation"):
		m.step = stepXUIConfirm
		m.inputError = message
	default:
		m.err = err
		m.step = stepError
	}
	return m
}

func appendWarnings(existing, incoming []string) []string {
	seen := map[string]bool{}
	for _, warning := range existing {
		seen[warning] = true
	}
	for _, warning := range incoming {
		if !seen[warning] {
			existing = append(existing, warning)
			seen[warning] = true
		}
	}
	return existing
}

func isSSHKeyError(lower string) bool {
	return strings.Contains(lower, "read ssh key") || strings.Contains(lower, "parse ssh key")
}

func isSSHKeyPassphraseError(lower string) bool {
	return strings.Contains(lower, "requires a passphrase") ||
		strings.Contains(lower, "decrypt ssh key") ||
		strings.Contains(lower, "incorrect passphrase")
}

func isSSHAuthError(lower string) bool {
	return strings.Contains(lower, "unable to authenticate") ||
		strings.Contains(lower, "no supported methods remain") ||
		strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "no ssh authentication method available")
}

func isSSHConnectError(lower string) bool {
	return strings.Contains(lower, "connect ssh") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "operation timed out") ||
		strings.Contains(lower, "no route to host")
}

func (m model) verifyTokenCmd() tea.Cmd {
	return func() tea.Msg {
		if err := m.provisioner.VerifyToken(context.Background(), m.tokenInput.Value(), m.accountInput.Value()); err != nil {
			return errorMsg{err: err}
		}
		return tokenVerifiedMsg{}
	}
}

func (m model) applyCmd() tea.Cmd {
	return func() tea.Msg {
		result, err := m.provisioner.Provision(context.Background(), types.ProvisionInput{
			Token:     m.tokenInput.Value(),
			AccountID: m.accountInput.Value(),
			Domain:    m.domainInput.Value(),
			VPSIP:     m.ipInput.Value(),
		})
		if err != nil {
			return errorMsg{err: err}
		}
		return resultMsg(result)
	}
}

func (m model) xuiInput(confirm bool) xui.Input {
	return xui.Input{
		Domain: m.domainInput.Value(),
		Root:   m.provisioner.Root,
		SSH: xui.SSHConfig{
			Host:          m.sshHostInput.Value(),
			User:          m.sshUserInput.Value(),
			Port:          22,
			KeyPath:       m.sshKeyInput.Value(),
			KeyPassphrase: m.sshKeyPassInput.Value(),
			Password:      m.sshPassInput.Value(),
		},
		ConfirmReplace: confirm,
	}
}

func (m model) xuiPlanCmd() tea.Cmd {
	return func() tea.Msg {
		plan, err := xui.NewProvisioner().Plan(context.Background(), m.xuiInput(false))
		if err != nil {
			return errorMsg{err: err}
		}
		return xuiPlanMsg(plan)
	}
}

func (m model) startXUIApply() (tea.Model, tea.Cmd) {
	ch := make(chan tea.Msg)
	input := m.xuiInput(len(m.xuiPlan.Conflicts) > 0)
	input.Progress = func(line string) {
		ch <- xuiProgressMsg(line)
	}
	m.step = stepXUIApplying
	m.xuiApplyLog = nil
	m.xuiProgress = ch
	return m, xuiApplyCmd(ch, input)
}

func xuiApplyCmd(ch chan tea.Msg, input xui.Input) tea.Cmd {
	return func() tea.Msg {
		go func() {
			result, err := xui.NewProvisioner().Apply(context.Background(), input)
			ch <- xuiApplyDoneMsg{result: result, err: err}
			close(ch)
		}()
		return <-ch
	}
}

func waitXUIProgressCmd(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		return <-ch
	}
}

func (m model) menuXUIInput(domain string) xui.Input {
	return xui.Input{
		Domain: domain,
		Root:   m.provisioner.Root,
		SSH: xui.SSHConfig{
			Host:          m.sshHostInput.Value(),
			User:          m.sshUserInput.Value(),
			Port:          22,
			KeyPath:       m.sshKeyInput.Value(),
			KeyPassphrase: m.sshKeyPassInput.Value(),
			Password:      m.sshPassInput.Value(),
		},
		ConfirmReplace: true,
	}
}

func (m model) menuActionCmd() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		provisioner := xui.NewProvisioner()
		oldDomain := m.selectedDomain()
		switch m.menuAction {
		case menuInfo:
			info, err := xui.LoadCurrentInfo(m.provisioner.Root, oldDomain)
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderCurrentInfo(info)}
		case menuDashboard:
			info, err := provisioner.DashboardInfo(oldDomain, m.provisioner.Root)
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderDashboardInfo(info)}
		case menuDiagnostics:
			result, err := provisioner.Diagnostics(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderDiagnostics(result)}
		case menuRepair:
			result, err := provisioner.RepairManaged(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderRepairResult(result)}
		case menuBackup:
			result, err := provisioner.BackupManaged(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderBackupResult(result)}
		case menuRestore:
			result, err := provisioner.RestoreLatestBackup(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderRestoreResult(result)}
		case menuSupportBundle:
			result, err := provisioner.SupportBundle(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderSupportBundleResult(result)}
		case menuInbounds:
			items, err := provisioner.ListInbounds(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderInbounds(items)}
		case menuOutbounds:
			items, err := provisioner.ListOutbounds(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderOutbounds(items)}
		case menuClients:
			items, err := provisioner.ListClients(ctx, m.menuXUIInput(oldDomain), 10)
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderClients(items)}
		case menuReset:
			result, err := provisioner.ResetManaged(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: "Reset complete.\n\n" + clientLinksCodeBlock(result)}
		case menuDelete:
			result, err := provisioner.DeleteManaged(ctx, m.menuXUIInput(oldDomain))
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: xui.RenderDeleteResult(result)}
		case menuChangeDomain:
			body, err := m.runChangeDomain(ctx, provisioner, oldDomain)
			if err != nil {
				return actionErrorMsg{err: err}
			}
			return actionResultMsg{title: menuActionTitle(m.menuAction), body: body}
		default:
			return actionErrorMsg{err: fmt.Errorf("unknown menu action")}
		}
	}
}

func (m model) runChangeDomain(ctx context.Context, provisioner xui.Provisioner, oldDomain string) (string, error) {
	creds, err := m.provisioner.LoadCredentials()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(creds.APIToken) == "" || strings.TrimSpace(creds.AccountID) == "" {
		return "", fmt.Errorf("saved Cloudflare account ID and API token are required")
	}
	newDomain, err := planner.NormalizeDomain(m.domainInput.Value())
	if err != nil {
		return "", err
	}
	ip, err := planner.ValidateIPv4(m.ipInput.Value())
	if err != nil {
		return "", err
	}
	cfResult, err := m.provisioner.Provision(ctx, types.ProvisionInput{
		Token:     creds.APIToken,
		AccountID: creds.AccountID,
		Domain:    newDomain,
		VPSIP:     ip,
		Root:      m.provisioner.Root,
	})
	if err != nil {
		return "", err
	}
	if err := xui.ReuseManagedSecrets(m.provisioner.Root, oldDomain, newDomain); err != nil {
		return "", err
	}
	xuiResult, err := provisioner.ResetManaged(ctx, m.menuXUIInput(newDomain))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Cloudflare updated for %s.\n", cfResult.Zone.Name)
	for _, result := range cfResult.DNSResults {
		fmt.Fprintf(&b, "%-10s %s\n", result.Status, result.Record.Name)
	}
	b.WriteString("\n3x-ui reapplied for new domain.\n\n")
	b.WriteString(clientLinksCodeBlock(xuiResult))
	return b.String(), nil
}

func (m model) handleMenuError(err error) model {
	lower := strings.ToLower(err.Error())
	switch {
	case isSSHKeyPassphraseError(lower):
		m.step = stepSSHKeyPassphrase
		m.sshKeyPassInput.Focus()
		m.inputError = "SSH key passphrase is required or incorrect."
	case isSSHKeyError(lower):
		m.step = stepSSHKey
		m.sshKeyInput.Focus()
		m.inputError = "SSH key could not be used."
	case isSSHAuthError(lower):
		m.step = stepSSHPassword
		m.sshPassInput.Focus()
		m.inputError = "SSH authentication failed. Re-enter SSH credentials and retry."
	case isSSHConnectError(lower):
		m.step = stepSSHHost
		m.sshHostInput.Focus()
		m.inputError = err.Error()
	default:
		m.actionTitle = menuActionTitle(m.menuAction)
		m.actionBody = err.Error()
		m.actionFailed = true
		m.step = stepActionDetail
	}
	return m
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
