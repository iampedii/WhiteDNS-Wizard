package planner

import (
	"fmt"
	"net"
	"strings"

	"github.com/whitedns/wdns-wizard/pkg/types"
)

func NormalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if strings.ContainsAny(domain, "/: ") {
		return "", fmt.Errorf("domain must be a bare DNS name")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain must include a TLD")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("domain has an invalid label")
		}
	}
	return domain, nil
}

func ValidateIPv4(ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("VPS IP must be a valid IPv4 address")
	}
	return ip, nil
}

// ValidateIranProfiles enforces the ArvanCloud collateral-freedom invariants:
//   - iran_xhttp_tls: TLS SNI must equal the HTTP Host (ArvanCloud returns 403 on
//     mismatch).
//   - iran_ws_none: must be security=none with no SNI, and the connect address
//     must differ from the HTTP Host (the decoy split is the whole point).
func ValidateIranProfiles(p types.Protocol) error {
	switch p.Name {
	case "iran_xhttp_tls":
		if p.ResolvedServerName() != p.ResolvedHost() {
			return fmt.Errorf("iran_xhttp_tls: SNI (%q) must equal Host (%q) — ArvanCloud returns 403 on mismatch",
				p.ResolvedServerName(), p.ResolvedHost())
		}
	case "iran_ws_none":
		if p.TLS || p.ServerName != "" {
			return fmt.Errorf("iran_ws_none: must be security=none with no SNI")
		}
		if p.ResolvedAddress() == p.ResolvedHost() {
			return fmt.Errorf("iran_ws_none: connect-address must differ from Host (decoy requires the split)")
		}
	}
	return nil
}

// ValidateIranPlan validates every Iran-domestic profile in a plan.
func ValidateIranPlan(plan types.ProtocolPlan) error {
	for _, proto := range plan.Protocols {
		if proto.Profile != "iran-domestic" {
			continue
		}
		if err := ValidateIranProfiles(proto); err != nil {
			return err
		}
	}
	return nil
}
