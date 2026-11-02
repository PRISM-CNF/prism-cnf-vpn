package vnf

import (
	"context"
	"fmt"

	"nse-ovs-vpn/internal/processor"
)

func DefaultRuleInstaller() RuleInstaller {
	return RuleInstallerFunc(installTrafficRules)
}

func installTrafficRules(_ context.Context, _ *SessionContext) (processor.Session, error) {
	return processor.CloseFunc(func(context.Context) error {
		return nil
	}), nil
}

func ensureRedirectRule(ctx context.Context, iface, protocol, port, comment string) error {
	checkArgs := append([]string{"-t", "nat", "-C", "PREROUTING"}, redirectRuleSpec(iface, protocol, port, comment)...)
	if err := runCommand(ctx, "iptables", checkArgs...); err == nil {
		return nil
	}

	addArgs := append([]string{"-t", "nat", "-A", "PREROUTING"}, redirectRuleSpec(iface, protocol, port, comment)...)
	if err := runCommand(ctx, "iptables", addArgs...); err != nil {
		return fmt.Errorf("install redirect rule on %s for %s/%s: %w", iface, protocol, port, err)
	}
	return nil
}

func deleteRedirectRule(ctx context.Context, iface, protocol, port, comment string) error {
	deleteArgs := append([]string{"-t", "nat", "-D", "PREROUTING"}, redirectRuleSpec(iface, protocol, port, comment)...)
	if err := runCommand(ctx, "iptables", deleteArgs...); err != nil {
		return fmt.Errorf("delete redirect rule on %s for %s/%s: %w", iface, protocol, port, err)
	}
	return nil
}

func redirectRuleSpec(iface, protocol, port, comment string) []string {
	return []string{
		"-i", iface,
		"-p", protocol,
		"-m", protocol,
		"--dport", port,
		"-m", "comment",
		"--comment", comment,
		"-j", "REDIRECT",
		"--to-ports", port,
	}
}
