//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"clatch-gateway/internal/firewall"
	"clatch-gateway/internal/guard"
	"clatch-gateway/internal/health"
	"clatch-gateway/internal/native"
	"clatch-gateway/internal/policy"
	"clatch-gateway/internal/system"
	"golang.org/x/net/dns/dnsmessage"
)

type policyTransaction struct {
	Schema     int             `json:"schema"`
	State      string          `json:"state"`
	Config     string          `json:"config"`
	BootID     string          `json:"boot_id"`
	Old        policy.Approved `json:"old"`
	Desired    policy.Approved `json:"desired"`
	Restricted policy.Approved `json:"restricted"`
}

func transactionPointer(config policy.Config) string {
	return filepath.Join(filepath.Dir(config.ApprovedPolicy), "clatch-policy-pending.json")
}

func transactionFile(directory string) string {
	return filepath.Join(directory, "transaction.json")
}

func PolicyTransaction(action, path, dir, source, geoIP string) (string, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return "", fmt.Errorf("transaction directory must be a canonical absolute path")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var result string
	err = WithLock(func() error {
		switch action {
		case "stage":
			result, err = stagePolicy(path, dir, source, geoIP)
		case "commit", "rollback":
			result, err = finishPolicy(path, dir, action)
		default:
			err = fmt.Errorf("unknown policy transaction action")
		}
		return err
	})
	return result, err
}

func InspectPolicy(path, geoIP string) (policy.Approved, error) {
	var result policy.Approved
	err := WithLock(func() error {
		config, err := policy.ReadConfig(path)
		if err != nil {
			return err
		}
		result, err = approvalFromSource(config, "", geoIP)
		return err
	})
	return result, err
}

func stagePolicy(path, directory, input, geoIP string) (string, error) {
	gate, err := open(path)
	if err != nil {
		return "", err
	}
	next, err := approvalFromSource(gate.Config, input, geoIP)
	if err != nil {
		return "", err
	}
	return stageApproval(gate, directory, next)
}

func approvalFromSource(config policy.Config, input, geoIP string) (policy.Approved, error) {
	if config.IsNative() {
		var raw json.RawMessage
		var err error
		if input == "" {
			raw, err = native.ReadWhitelist(config)
		} else {
			raw, err = os.ReadFile(input)
		}
		if err != nil {
			return policy.Approved{}, err
		}
		return native.Approval(config, raw, geoIP)
	}
	if config.Proxy == nil || geoIP != "" {
		return policy.Approved{}, fmt.Errorf("standalone policy requires a configured backend and explicit CIDRs")
	}
	if input == "" {
		input = config.Proxy.PolicySource
	}
	source, err := policy.ReadSource(input)
	if err != nil {
		return policy.Approved{}, err
	}
	return config.ApprovalFor(source)
}

func stageApproval(gate *Gate, directory string, next policy.Approved) (string, error) {
	path, err := filepath.Abs(gate.Path)
	if err != nil {
		return "", err
	}
	if _, found, err := savedTransaction(gate.Config, path); err != nil {
		return "", err
	} else if found {
		return "", fmt.Errorf("an unfinished policy transaction exists")
	}
	if _, err := gate.Verify(); err != nil {
		return "", err
	}
	if gate.Config.IsNative() {
		if err := native.CheckWhitelist(gate.Config, gate.Approved); err != nil {
			return "", err
		}
	}
	restricted, err := restrictPolicy(gate.Config, gate.Approved, next)
	if err != nil {
		return "", err
	}
	boot, err := bootID()
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", err
	}
	tx := policyTransaction{
		Schema: 1, State: "prepared", Config: path, BootID: boot,
		Old: gate.Approved, Desired: next, Restricted: restricted,
	}
	if err := putJSON(transactionFile(directory), tx); err != nil {
		return "", err
	}
	if err := putJSON(transactionPointer(gate.Config), directory); err != nil {
		return "", err
	}
	if err := applyTransaction(gate, restricted, true); err != nil {
		return "", err
	}
	tx.State = "staged"
	return tx.State, putJSON(transactionFile(directory), tx)
}

func restrictPolicy(config policy.Config, old, next policy.Approved) (policy.Approved, error) {
	shared := policy.Intersect(old.Prefixes, next.Prefixes)
	restricted := old
	restricted.Transition = json.RawMessage("true")
	restricted.Networks = policy.Strings(shared)
	restricted.NetworkSHA256 = policy.Digest(shared)
	return config.ValidateApproved(restricted)
}

func savedTransaction(config policy.Config, path string) (policyTransaction, bool, error) {
	var tx policyTransaction
	raw, err := os.ReadFile(transactionPointer(config))
	if errors.Is(err, os.ErrNotExist) {
		return tx, false, nil
	}
	if err != nil {
		return tx, false, err
	}
	var directory string
	if err := json.Unmarshal(raw, &directory); err != nil {
		return tx, false, err
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return tx, false, fmt.Errorf("invalid policy transaction ownership path")
	}
	raw, err = os.ReadFile(transactionFile(directory))
	if err != nil {
		return tx, false, err
	}
	if err := json.Unmarshal(raw, &tx); err != nil {
		return tx, false, err
	}
	canonical, err := filepath.Abs(path)
	if err != nil {
		return tx, false, err
	}
	if tx.Schema != 1 || tx.Config != canonical {
		return tx, false, fmt.Errorf("policy transaction belongs to another gateway")
	}
	tx.Old, err = config.ValidateApproved(tx.Old)
	if err != nil {
		return tx, false, err
	}
	tx.Desired, err = config.ValidateApproved(tx.Desired)
	if err != nil {
		return tx, false, err
	}
	expected, err := restrictPolicy(config, tx.Old, tx.Desired)
	if err != nil {
		return tx, false, err
	}
	if expected.NetworkSHA256 != tx.Restricted.NetworkSHA256 {
		return tx, false, fmt.Errorf("transaction restriction differs from the old and desired policy intersection")
	}
	tx.Restricted = expected
	return tx, true, nil
}

func verifySource(config policy.Config, approved policy.Approved, path string) error {
	tx, exists, err := savedTransaction(config, path)
	if err != nil {
		return err
	}
	if !exists {
		return config.CheckSource(approved)
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if tx.State != "staged" || tx.BootID != boot || approved.NetworkSHA256 != tx.Restricted.NetworkSHA256 {
		return fmt.Errorf("active policy transaction requires completion or recovery")
	}
	if config.CheckSource(tx.Old) != nil && config.CheckSource(tx.Desired) != nil {
		return fmt.Errorf("standalone source diverged from both sides of the policy transaction")
	}
	return nil
}

func finishPolicy(path, directory, action string) (string, error) {
	config, err := policy.ReadConfig(path)
	if err != nil {
		return "", err
	}
	tx, exists, err := savedTransaction(config, path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("no pending Clatch policy transaction")
	}
	var owned string
	pointer, err := os.ReadFile(transactionPointer(config))
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(pointer, &owned); err != nil || owned != directory {
		return "", fmt.Errorf("requested transaction directory differs from its ownership record")
	}
	boot, err := bootID()
	if err != nil {
		return "", err
	}
	target, status := tx.Old, "rolled_back"
	if action == "commit" {
		if tx.State != "staged" && tx.State != "committed" || tx.BootID != boot {
			return "", fmt.Errorf("only a staged transaction in this boot can commit")
		}
		target, status = tx.Desired, "committed"
	} else if tx.State == "committed" {
		return "", fmt.Errorf("a committed transaction cannot be rolled back as a pending update")
	}
	if err := checkTransactionSource(config, target); err != nil {
		return "", err
	}
	if action == "commit" {
		if config.IsNative() {
			if err := native.CheckApproved(config, target); err != nil {
				return "", err
			}
			capture := target
			if config.NativeTUN {
				capture = tx.Restricted
			}
			if err := native.VerifyCapture(config, capture); err != nil {
				return "", err
			}
			if err := verifyDNSAt(config.NativeService, nativeDNS, []string{"www.baidu.com.", "ip.fm."}); err != nil {
				return "", err
			}
		} else if err := verifyDNS(config.Proxy); err != nil {
			return "", err
		}
	}
	gate := &Gate{Config: config, Approved: target, Path: path}
	if err := applyTransaction(gate, target, false); err != nil {
		return "", err
	}
	tx.State = status
	if err := putJSON(transactionFile(directory), tx); err != nil {
		return "", err
	}
	return status, os.Remove(transactionPointer(config))
}

func applyTransaction(gate *Gate, target policy.Approved, shrinking bool) error {
	settings, err := gate.settings(false)
	if err != nil {
		return err
	}
	verify := guard.VerifyStandalone
	if gate.Config.IsTUN() {
		verify = guard.Verify
	}
	if _, err := verify(gate.Config.Interface, gate.Config.Pins); err != nil {
		return err
	}
	if err := putJSON(gate.Config.ApprovedPolicy, target); err != nil {
		return err
	}
	entries := gate.Config.Entries(target)
	if shrinking {
		if err := guard.UpdatePolicy(gate.Config.Pins, entries); err != nil {
			return err
		}
	}
	rules, err := firewall.RenderGuard(gate.Config, target, settings.TrustedTUNIfindex)
	if err != nil {
		return err
	}
	if err := firewall.Apply(rules, gate.Config.RulesFile, gate.fingerprintPath()); err != nil {
		return err
	}
	if gate.Config.NativeTUN && settings.TrustedTUNIfindex != 0 {
		if err := native.InstallCapture(gate.Config, target); err != nil {
			return err
		}
	}
	if !shrinking {
		if err := guard.UpdatePolicy(gate.Config.Pins, entries); err != nil {
			return err
		}
	}
	gate.Approved = target
	_, err = gate.Verify()
	return err
}

const nativeDNS = "127.2.0.17:53"

func CheckBackendDNS(config policy.Config) error {
	if config.IsNative() {
		return verifyDNSAt(config.NativeService, nativeDNS, []string{"www.baidu.com.", "ip.fm."})
	}
	return verifyDNS(config.Proxy)
}

func verifyDNS(proxy *policy.Proxy) error {
	address := net.JoinHostPort(proxy.DNSAddress, strconv.Itoa(int(proxy.DNSPort)))
	return verifyDNSAt(proxy.Service, address, []string{"www.baidu.com."})
}

func verifyDNSAt(service, address string, names []string) error {
	if _, err := system.Command("", "systemctl", "is-active", "--quiet", service); err != nil {
		return fmt.Errorf("proxy service must be running before policy commit: %w", err)
	}
	server, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	for _, name := range names {
		for _, network := range []string{"udp4", "tcp4"} {
			if _, err := health.DNS(context.Background(), server, network, name, dnsmessage.TypeA, false); err != nil {
				return fmt.Errorf("proxy DNS is not ready for %s over %s: %w", name, network, err)
			}
		}
	}
	return nil
}

func checkTransactionSource(config policy.Config, approved policy.Approved) error {
	if config.IsNative() {
		if err := native.CheckWhitelist(config, approved); err != nil {
			return err
		}
		return native.CheckSavedGeoIP(config, approved)
	}
	return config.CheckSource(approved)
}

func recoverPolicy(config policy.Config, path string) error {
	tx, exists, err := savedTransaction(config, path)
	if err != nil || !exists {
		return err
	}
	if checkTransactionSource(config, tx.Old) != nil && checkTransactionSource(config, tx.Desired) != nil {
		return fmt.Errorf("policy recovery cannot identify the current source")
	}
	raw, err := os.ReadFile(transactionPointer(config))
	if err != nil {
		return err
	}
	var directory string
	if err := json.Unmarshal(raw, &directory); err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if tx.State == "committed" || tx.State == "rolled_back" || tx.State == "boot_rolled_back" {
		target := tx.Old
		if tx.State == "committed" {
			target = tx.Desired
		}
		if err := checkTransactionSource(config, target); err != nil {
			return err
		}
		if err := putJSON(config.ApprovedPolicy, target); err != nil {
			return err
		}
		return os.Remove(transactionPointer(config))
	}
	if tx.State != "prepared" && tx.State != "staged" {
		return fmt.Errorf("unrecognized pending policy status")
	}
	if tx.BootID == boot {
		gate := &Gate{Config: config, Approved: tx.Restricted, Path: path}
		if err := applyTransaction(gate, tx.Restricted, true); err != nil {
			return err
		}
		tx.State = "staged"
		return putJSON(transactionFile(directory), tx)
	}
	// Recover the old source before either the backend or the network is opened.
	service := config.NativeService
	if config.Proxy != nil {
		service = config.Proxy.Service
	}
	if err := requireInactive(service); err != nil {
		return err
	}
	if config.IsNative() {
		if err := native.CheckSavedGeoIP(config, tx.Old); err != nil {
			return err
		}
		current, err := native.ReadWhitelist(config)
		if err != nil {
			return err
		}
		if !native.SameWhitelist(current, tx.Old.Whitelist) {
			if !native.SameWhitelist(current, tx.Desired.Whitelist) {
				return fmt.Errorf("concurrent native whitelist change")
			}
			if err := native.ReplaceWhitelist(config, tx.Desired.Whitelist, tx.Old.Whitelist); err != nil {
				return err
			}
		}
	} else if err := system.WriteAtomic(config.Proxy.PolicySource, append(tx.Old.SourcePolicy, '\n'), 0600); err != nil {
		return err
	}
	if err := putJSON(config.ApprovedPolicy, tx.Old); err != nil {
		return err
	}
	tx.State = "boot_rolled_back"
	if err := putJSON(transactionFile(directory), tx); err != nil {
		return err
	}
	return os.Remove(transactionPointer(config))
}

func requireInactive(service string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", service)
	exit, stopped := command.Run().(*exec.ExitError)
	if !stopped || exit.ExitCode() != 3 {
		return fmt.Errorf("policy recovery requires a stopped proxy service")
	}
	return nil
}
