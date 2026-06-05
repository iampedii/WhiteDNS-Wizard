package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/whitedns/wdns-wizard/internal/app"
	"github.com/whitedns/wdns-wizard/internal/output"
	"github.com/whitedns/wdns-wizard/internal/planner"
	"github.com/whitedns/wdns-wizard/internal/tui"
	"github.com/whitedns/wdns-wizard/internal/xui"
	"github.com/whitedns/wdns-wizard/pkg/types"
	"golang.org/x/term"
)

var runTUI = tui.Run

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func NewRootCommand() *cobra.Command {
	var root string
	var accountID string
	cmd := &cobra.Command{
		Use:     "whitedns",
		Short:   "Cloudflare-first VPN provisioning wizard",
		Version: buildVersion(),
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractiveWizard(root, accountID)
		},
	}
	cmd.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	cmd.PersistentFlags().StringVar(&root, "root", "", "project output root")
	cmd.PersistentFlags().StringVar(&accountID, "account-id", app.ResolveAccountID(""), "Cloudflare account ID for account-token verification")

	cmd.AddCommand(newInitCommand(&root, &accountID))
	cmd.AddCommand(newCloudflareCommand(&root, &accountID))
	cmd.AddCommand(newPlanCommand(&root))
	cmd.AddCommand(newXUICommand(&root))
	cmd.AddCommand(newIranCommand(&root))
	return cmd
}

func buildVersion() string {
	return fmt.Sprintf("%s commit=%s built=%s", version, commit, date)
}

func newInitCommand(root, accountID *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Run the interactive provisioning wizard",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractiveWizard(*root, *accountID)
		},
	}
}

func runInteractiveWizard(root, accountID string) error {
	provisioner := app.NewProvisioner(root)
	provisioner.AccountID = app.ResolveAccountID(accountID)
	return runTUI(provisioner)
}

func newCloudflareCommand(root, accountID *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloudflare",
		Short: "Cloudflare checks and provisioning",
	}
	cmd.AddCommand(newCloudflareCheckCommand(root, accountID))
	cmd.AddCommand(newCloudflareApplyCommand(root, accountID))
	return cmd
}

func newCloudflareCheckCommand(root, accountID *string) *cobra.Command {
	var token string
	var domain string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate token and optionally inspect a zone",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			provisioner := app.NewProvisioner(*root)
			token, *accountID, err = cloudflareInputsFromFlagEnvSavedOrPrompt(cmd, provisioner, token, *accountID)
			if err != nil {
				return err
			}
			provisioner.AccountID = app.ResolveAccountID(*accountID)
			zone, zones, err := provisioner.Check(context.Background(), token, *accountID, domain)
			if err != nil {
				return err
			}
			if zone != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Token valid. Zone %s is %s.\n", zone.Name, zone.Status)
				if len(zone.NameServers) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "Nameservers: %s\n", strings.Join(zone.NameServers, ", "))
				}
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Token valid. Found %d zone(s).\n", len(zones))
			for _, item := range zones {
				fmt.Fprintf(cmd.OutOrStdout(), "- %s (%s)\n", item.Name, item.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "Cloudflare API token; prompts when omitted")
	cmd.Flags().StringVar(&domain, "domain", "", "domain to inspect")
	return cmd
}

func newCloudflareApplyCommand(root, accountID *string) *cobra.Command {
	var token string
	var domain string
	var ip string
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply Cloudflare DNS, SSL, Origin CA, and local project output",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			provisioner := app.NewProvisioner(*root)
			token, *accountID, err = cloudflareInputsFromFlagEnvSavedOrPrompt(cmd, provisioner, token, *accountID)
			if err != nil {
				return err
			}
			provisioner.AccountID = app.ResolveAccountID(*accountID)
			result, err := provisioner.Provision(context.Background(), types.ProvisionInput{
				Token:     token,
				AccountID: *accountID,
				Domain:    domain,
				VPSIP:     ip,
				Root:      *root,
			})
			if err != nil {
				if inactive, ok := err.(types.InactiveZoneError); ok {
					fmt.Fprintf(cmd.ErrOrStderr(), "Zone %s is not active.\n", inactive.Zone.Name)
					if len(inactive.Zone.NameServers) > 0 {
						fmt.Fprintf(cmd.ErrOrStderr(), "Update registrar nameservers to: %s\n", strings.Join(inactive.Zone.NameServers, ", "))
					}
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Cloudflare setup complete for %s.\n", result.Zone.Name)
			for _, record := range result.DNSResults {
				fmt.Fprintf(cmd.OutOrStdout(), "%-10s %s\n", record.Status, record.Record.Name)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Project written to %s\n", result.ProjectDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "Cloudflare API token; prompts when omitted")
	cmd.Flags().StringVar(&domain, "domain", "", "domain to provision")
	cmd.Flags().StringVar(&ip, "ip", "", "VPS IPv4 address")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("ip")
	return cmd
}

func newPlanCommand(root *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Read generated provisioning plans",
	}
	cmd.AddCommand(newPlanShowCommand(root))
	return cmd
}

func newPlanShowCommand(root *string) *cobra.Command {
	return &cobra.Command{
		Use:   "show <domain>",
		Short: "Show generated DNS and protocol plans",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, err := planner.NormalizeDomain(args[0])
			if err != nil {
				return err
			}
			projectRoot := *root
			if projectRoot == "" {
				projectRoot, err = output.DefaultRoot()
				if err != nil {
					return err
				}
			}
			paths := output.Paths(projectRoot, domain)
			for _, file := range []string{paths.DNSPlan, paths.ProtocolPlan} {
				body, err := os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("read %s: %w", file, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "# %s\n%s\n", filepath.Base(file), strings.TrimRight(string(body), "\n"))
			}
			return nil
		},
	}
}

type xuiFlags struct {
	domain        string
	sshHost       string
	sshUser       string
	sshPort       int
	sshKey        string
	sshKeyPass    string
	sshPassword   string
	panelUsername string
	panelPassword string
	panelBasePath string
	acmeEmail     string
	yes           bool
}

func newXUICommand(root *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "xui",
		Short: "3x-ui checks and provisioning over SSH",
	}
	cmd.AddCommand(newXUICheckCommand(root))
	cmd.AddCommand(newXUIPlanCommand(root))
	cmd.AddCommand(newXUIApplyCommand(root))
	return cmd
}

func newXUICheckCommand(root *string) *cobra.Command {
	flags := addXUIFlags(&cobra.Command{
		Use:   "check",
		Short: "Check SSH and 3x-ui installation status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}, false)
	cmd := flags.cmd
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		input := xuiInputFromFlags(*root, flags)
		plan, err := xui.NewProvisioner().Plan(context.Background(), input)
		if err != nil {
			return err
		}
		printXUIPlan(cmd, plan)
		return nil
	}
	return cmd
}

func newXUIPlanCommand(root *string) *cobra.Command {
	flags := addXUIFlags(&cobra.Command{
		Use:   "plan",
		Short: "Generate and show the 3x-ui provisioning plan",
	}, false)
	cmd := flags.cmd
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		input := xuiInputFromFlags(*root, flags)
		plan, err := xui.NewProvisioner().Plan(context.Background(), input)
		if err != nil {
			return err
		}
		printXUIPlan(cmd, plan)
		return nil
	}
	return cmd
}

func newXUIApplyCommand(root *string) *cobra.Command {
	flags := addXUIFlags(&cobra.Command{
		Use:   "apply",
		Short: "Apply 3x-ui Docker, inbounds, outbounds, certificates, and clients",
	}, true)
	cmd := flags.cmd
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		input := xuiInputFromFlags(*root, flags)
		result, err := xui.NewProvisioner().Apply(context.Background(), input)
		if err != nil {
			var conflict xui.ConflictError
			if errors.As(err, &conflict) {
				fmt.Fprintln(cmd.ErrOrStderr(), "3x-ui conflicts detected. Re-run with --yes to replace these entries:")
				for _, item := range conflict.Conflicts {
					fmt.Fprintf(cmd.ErrOrStderr(), "- %-8s %-18s %s\n", item.Kind, item.Name, item.Detail)
				}
			}
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "3x-ui setup complete for %s.\n", result.Plan.Domain)
		for _, client := range result.Links.Clients {
			fmt.Fprintf(cmd.OutOrStdout(), "\n# %s\n%s\n", client.Name, client.Link)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\nProject written to %s\n", result.ProjectDir)
		return nil
	}
	return cmd
}

type iranFlags struct {
	domain      string
	frontDomain string
	cdnHost     string
	cdnPort     int
	wsFront     string
	wsAddress   string
	wsPort      int
	tcpHost     string
	tcpPort     int
}

func newIranCommand(root *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iran",
		Short: "Iran domestic-CDN fronting profiles (ArvanCloud collateral freedom)",
		Long:  "Generate Iran domestic-fronting VLESS profiles (XHTTP-over-TLS, WS security=none, TCP+HTTP-header) with no Cloudflare token or ACME dependency. The CDN is assumed to exist; a manual ArvanCloud checklist is printed alongside the client links.",
	}
	cmd.AddCommand(newIranPlanCommand(root))
	cmd.AddCommand(newIranApplyCommand(root))
	return cmd
}

func addIranFlags(cmd *cobra.Command) *iranFlags {
	flags := &iranFlags{}
	cmd.Flags().StringVar(&flags.domain, "domain", "iran-domestic.local", "logical project name used for client remarks (no Cloudflare zone required)")
	cmd.Flags().StringVar(&flags.frontDomain, "front-domain", "", ".ir front (SNI == Host) for the XHTTP-TLS profile; defaults to the owner-controlled abshardejh.ir seed")
	cmd.Flags().StringVar(&flags.cdnHost, "cdn-host", "", "connect address (clean ArvanCloud edge host/IP) for the XHTTP-TLS profile")
	cmd.Flags().IntVar(&flags.cdnPort, "cdn-port", 2053, "edge port for the XHTTP-TLS profile (2053/2083/2087/8443)")
	cmd.Flags().StringVar(&flags.wsFront, "ws-front", "", ".ir HTTP Host header for the WS-none profile (must differ from --ws-address)")
	cmd.Flags().StringVar(&flags.wsAddress, "ws-address", "", "high-collateral .ir connect decoy for the WS-none profile")
	cmd.Flags().IntVar(&flags.wsPort, "ws-port", 8880, "edge port for the WS-none profile (8880/2086/8080/2095/2052)")
	cmd.Flags().StringVar(&flags.tcpHost, "tcp-host", "", "camouflage .ir host for the TCP+HTTP-header profile")
	cmd.Flags().IntVar(&flags.tcpPort, "tcp-port", 56201, "L4 passthrough port for the TCP+HTTP-header profile (56201-56207)")
	return flags
}

func iranFrontingFromFlags(flags *iranFlags) planner.IranFrontingInput {
	return planner.IranFrontingInput{
		Front:     flags.frontDomain,
		CDNHost:   flags.cdnHost,
		CDNPort:   flags.cdnPort,
		WSFront:   flags.wsFront,
		WSAddress: flags.wsAddress,
		WSPort:    flags.wsPort,
		TCPHost:   flags.tcpHost,
		TCPPort:   flags.tcpPort,
	}
}

func newIranPlanCommand(root *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Print the Iran domestic-fronting client links and the manual ArvanCloud checklist (dry-run)",
	}
	flags := addIranFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		bundle, err := buildIranBundleForCLI(flags)
		if err != nil {
			return err
		}
		printIranBundle(cmd, bundle)
		return nil
	}
	return cmd
}

func newIranApplyCommand(root *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Push Iran domestic-fronting inbounds via the existing SSH tunnel (no Cloudflare/ACME)",
	}
	flags := addIranFlags(cmd)
	// Apply needs SSH details, but the Iran path never reads a Cloudflare token.
	var sshHost, sshUser, sshKey, sshPassword string
	var sshPort int
	cmd.Flags().StringVar(&sshHost, "ssh-host", "", "VPS SSH host or IP")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "VPS SSH user")
	cmd.Flags().IntVar(&sshPort, "ssh-port", 22, "VPS SSH port")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH private key path")
	cmd.Flags().StringVar(&sshPassword, "ssh-password", "", "SSH password; not saved")
	_ = cmd.MarkFlagRequired("ssh-host")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		bundle, err := buildIranBundleForCLI(flags)
		if err != nil {
			return err
		}
		printIranBundle(cmd, bundle)
		fmt.Fprintf(cmd.OutOrStdout(), "\nApply target: %s@%s:%d (CertMode=origin-http; no Cloudflare/ACME).\n", sshUser, sshHost, sshPort)
		fmt.Fprintln(cmd.OutOrStdout(), "Inbounds ride the existing SSH-tunnel AddInbound machinery once the managed 3x-ui stack is reachable.")
		return nil
	}
	return cmd
}

func buildIranBundleForCLI(flags *iranFlags) (xui.ProtocolBundle, error) {
	values := map[string]string{
		"iran_xhttp_uuid": "00000000-0000-0000-0000-000000000001",
		"iran_ws_uuid":    "00000000-0000-0000-0000-000000000002",
		"iran_tcp_uuid":   "00000000-0000-0000-0000-000000000003",
		"iran_ws_path":    "/filmonline?ed=2048",
	}
	return xui.BuildIranProtocolBundle(flags.domain, iranFrontingFromFlags(flags), values)
}

func printIranBundle(cmd *cobra.Command, bundle xui.ProtocolBundle) {
	fmt.Fprintln(cmd.OutOrStdout(), "Iran domestic-fronting profiles (Cloudflare-decoupled):")
	for _, client := range bundle.Links.Clients {
		fmt.Fprintf(cmd.OutOrStdout(), "\n# %s\n%s\n", client.Name, client.Link)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "\n"+xui.RenderIranChecklist())
}

type xuiFlagSet struct {
	cmd *cobra.Command
	xuiFlags
}

func addXUIFlags(cmd *cobra.Command, includeApply bool) *xuiFlagSet {
	flags := &xuiFlagSet{cmd: cmd}
	cmd.Flags().StringVar(&flags.domain, "domain", "", "domain to provision")
	cmd.Flags().StringVar(&flags.sshHost, "ssh-host", "", "VPS SSH host or IP")
	cmd.Flags().StringVar(&flags.sshUser, "ssh-user", "root", "VPS SSH user")
	cmd.Flags().IntVar(&flags.sshPort, "ssh-port", 22, "VPS SSH port")
	cmd.Flags().StringVar(&flags.sshKey, "ssh-key", "", "SSH private key path")
	cmd.Flags().StringVar(&flags.sshKeyPass, "ssh-key-passphrase", "", "SSH private key passphrase; used only with --ssh-key and not saved")
	cmd.Flags().StringVar(&flags.sshPassword, "ssh-password", "", "SSH password; not saved")
	cmd.Flags().StringVar(&flags.panelUsername, "panel-username", "", "existing 3x-ui panel username")
	cmd.Flags().StringVar(&flags.panelPassword, "panel-password", "", "existing 3x-ui panel password; saved encrypted if provided")
	cmd.Flags().StringVar(&flags.panelBasePath, "panel-base-path", "", "existing 3x-ui web base path")
	cmd.Flags().StringVar(&flags.acmeEmail, "acme-email", "", "ACME account email; defaults to admin@domain")
	if includeApply {
		cmd.Flags().BoolVar(&flags.yes, "yes", false, "confirm replacement of conflicting WhiteDNS or port-matching 3x-ui entries")
	}
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("ssh-host")
	return flags
}

func xuiInputFromFlags(root string, flags *xuiFlagSet) xui.Input {
	return xui.Input{
		Domain: flags.domain,
		Root:   root,
		SSH: xui.SSHConfig{
			Host:          flags.sshHost,
			User:          flags.sshUser,
			Port:          flags.sshPort,
			KeyPath:       flags.sshKey,
			KeyPassphrase: flags.sshKeyPass,
			Password:      flags.sshPassword,
		},
		Panel: xui.PanelCredentials{
			Username:    flags.panelUsername,
			Password:    flags.panelPassword,
			WebBasePath: flags.panelBasePath,
		},
		ConfirmReplace: flags.yes,
		ACMEEmail:      flags.acmeEmail,
	}
}

func printXUIPlan(cmd *cobra.Command, plan types.XUIPlan) {
	fmt.Fprintf(cmd.OutOrStdout(), "3x-ui plan for %s\n", plan.Domain)
	if plan.InstallRequired {
		fmt.Fprintln(cmd.OutOrStdout(), "Install: required")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "Install: existing Docker 3x-ui detected")
	}
	if len(plan.Warnings) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nWarnings:")
		for _, warning := range plan.Warnings {
			fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", warning)
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "\nProtocols:")
	for _, proto := range plan.Protocols {
		if !proto.Enabled {
			continue
		}
		network := proto.Network
		if network == "" {
			network = "tcp"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "- %-24s %s:%d/%s %s\n", xui.DisplayNameForTag(proto.Tag), proto.Hostname, proto.Port, network, proto.Transport)
	}
	if len(plan.Conflicts) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nConflicts:")
		for _, conflict := range plan.Conflicts {
			fmt.Fprintf(cmd.OutOrStdout(), "- %-8s %-18s %s\n", conflict.Kind, conflict.Name, conflict.Detail)
		}
	}
}

func cloudflareInputsFromFlagEnvSavedOrPrompt(cmd *cobra.Command, provisioner app.Provisioner, token, accountID string) (string, string, error) {
	saved, _ := provisioner.LoadCredentials()
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		accountID = strings.TrimSpace(os.Getenv("CLOUDFLARE_ACCOUNT_ID"))
	}
	if accountID == "" {
		accountID = strings.TrimSpace(saved.AccountID)
	}
	if accountID == "" {
		var err error
		accountID, err = promptLine(cmd, "Cloudflare account ID: ")
		if err != nil {
			return "", "", err
		}
	}

	token = strings.TrimSpace(token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(saved.APIToken)
	}
	if token == "" {
		var err error
		token, err = promptPassword(cmd, "Cloudflare API token: ")
		if err != nil {
			return "", "", err
		}
	}

	if accountID == "" {
		return "", "", fmt.Errorf("Cloudflare account ID is required")
	}
	if token == "" {
		return "", "", fmt.Errorf("Cloudflare API token is required")
	}
	return token, accountID, nil
}

func promptLine(cmd *cobra.Command, label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("Cloudflare account ID is required; pass --account-id, set CLOUDFLARE_ACCOUNT_ID, or run in an interactive terminal")
	}
	fmt.Fprint(cmd.ErrOrStderr(), label)
	raw, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read Cloudflare account ID: %w", err)
	}
	return strings.TrimSpace(raw), nil
}

func promptPassword(cmd *cobra.Command, label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("Cloudflare API token is required; pass --token, set CLOUDFLARE_API_TOKEN, or run in an interactive terminal")
	}
	fmt.Fprint(cmd.ErrOrStderr(), label)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", fmt.Errorf("read Cloudflare API token: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}
