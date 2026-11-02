package vnf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/vishvananda/netlink"

	"nse-ovs-vpn/internal/processor"
)

var globalVPNManager vpnManager

const wireGuardReadyTimeout = 12 * time.Second

type vpnManager struct {
	mu   sync.Mutex
	svc  *vpnService
	refs int
}

type vpnSession struct {
	once    sync.Once
	release func(context.Context) error
}

func (s *vpnSession) Close(ctx context.Context) error {
	if s == nil || s.release == nil {
		return nil
	}
	var result error
	s.once.Do(func() {
		result = s.release(ctx)
	})
	return result
}

type vpnBinding struct {
	clearLinkName     string
	transportLinkName string
	clearSourceIP     net.IP
}

func (b vpnBinding) clone() vpnBinding {
	return vpnBinding{
		clearLinkName:     b.clearLinkName,
		transportLinkName: b.transportLinkName,
		clearSourceIP:     cloneIP(b.clearSourceIP),
	}
}

func (b vpnBinding) equal(other vpnBinding) bool {
	return b.clearLinkName == other.clearLinkName &&
		b.transportLinkName == other.transportLinkName &&
		ipEqual(b.clearSourceIP, other.clearSourceIP)
}

type vpnService struct {
	key                   string
	role                  string
	stateMu               sync.RWMutex
	clearLinkName         string
	transportLinkName     string
	transportAddr         *netlink.Addr
	transportPeerIP       net.IP
	innerAddr             *netlink.Addr
	innerLocalIP          net.IP
	innerPeerIP           net.IP
	clearSourceIP         net.IP
	wgInterface           string
	wgListenPort          int
	wgPrivateKeyPath      string
	wgPeerPublicKey       string
	wgPersistentKeepalive int
	proxyPort             int
	targetIP              net.IP
	listeners             []io.Closer
	serviceCtx            context.Context
	serviceCancel         context.CancelFunc
	wgCancel              context.CancelFunc
	wgCmd                 *exec.Cmd
}

func (m *vpnManager) Start(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error) {
	if sessionCtx == nil || sessionCtx.Config() == nil {
		return nil, fmt.Errorf("session context and config are required")
	}

	svc, err := newVPNService(sessionCtx)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.svc != nil {
		if m.svc.key != svc.key {
			return nil, fmt.Errorf("vpn service already running for %s", m.svc.key)
		}
		if err := m.svc.rebind(ctx, svc.bindingSnapshot()); err != nil {
			return nil, err
		}
		m.refs++
		return &vpnSession{release: m.release}, nil
	}

	if err := svc.start(ctx); err != nil {
		return nil, err
	}

	m.svc = svc
	m.refs = 1
	return &vpnSession{release: m.release}, nil
}

func (m *vpnManager) release(ctx context.Context) error {
	m.mu.Lock()
	if m.refs > 0 {
		m.refs--
	}
	if m.refs > 0 || m.svc == nil {
		m.mu.Unlock()
		return nil
	}
	svc := m.svc
	m.svc = nil
	m.refs = 0
	m.mu.Unlock()
	return svc.stop(ctx)
}

func newVPNService(sessionCtx *SessionContext) (*vpnService, error) {
	cfg := sessionCtx.Config()
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	transportLink := sessionCtx.TransportLink()
	clearLink := sessionCtx.ClearLink()
	if transportLink == nil {
		return nil, fmt.Errorf("transport link is required")
	}

	transportAddr, transportPeerIP, err := roleCIDRAddr(cfg.VPNTransportCIDR, cfg.VPNRole)
	if err != nil {
		return nil, fmt.Errorf("resolve transport CIDR: %w", err)
	}
	innerAddr, innerPeerIP, err := roleCIDRAddr(cfg.VPNInnerCIDR, cfg.VPNRole)
	if err != nil {
		return nil, fmt.Errorf("resolve inner CIDR: %w", err)
	}

	peerPublicKey, err := readTrimmedFile(cfg.VPNPeerPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read WireGuard peer public key: %w", err)
	}

	targetIP := net.ParseIP(cfg.VPNTargetIP).To4()
	if targetIP == nil {
		return nil, fmt.Errorf("invalid VPN target IP %q", cfg.VPNTargetIP)
	}

	clearInterface := sessionCtx.ClearInterface()
	if clearInterface == "" {
		return nil, fmt.Errorf("clear-side interface is required")
	}

	clearSourceIP, err := resolveClearSourceIP(sessionCtx, clearLink)
	if err != nil {
		return nil, fmt.Errorf("resolve clear-side source IP on %s: %w", clearInterface, err)
	}

	binding := vpnBinding{
		clearLinkName:     clearInterface,
		transportLinkName: transportLink.Attrs().Name,
		clearSourceIP:     clearSourceIP,
	}

	return &vpnService{
		key: fmt.Sprintf(
			"role=%s outer=%s inner=%s target=%s port=%d wg=%s listen=%d",
			cfg.VPNRole,
			cfg.VPNTransportCIDR,
			cfg.VPNInnerCIDR,
			targetIP.String(),
			cfg.VPNProxyPort,
			cfg.VPNInterfaceName,
			cfg.VPNListenPort,
		),
		role:                  cfg.VPNRole,
		clearLinkName:         binding.clearLinkName,
		transportLinkName:     binding.transportLinkName,
		transportAddr:         transportAddr,
		transportPeerIP:       transportPeerIP,
		innerAddr:             innerAddr,
		innerLocalIP:          innerAddr.IPNet.IP,
		innerPeerIP:           innerPeerIP,
		clearSourceIP:         binding.clearSourceIP,
		wgInterface:           cfg.VPNInterfaceName,
		wgListenPort:          cfg.VPNListenPort,
		wgPrivateKeyPath:      cfg.VPNPrivateKeyPath,
		wgPeerPublicKey:       peerPublicKey,
		wgPersistentKeepalive: cfg.VPNPersistentKeepalive,
		proxyPort:             cfg.VPNProxyPort,
		targetIP:              targetIP,
	}, nil
}

func (s *vpnService) start(ctx context.Context) error {
	logger := log.FromContext(ctx)

	serviceCtx, serviceCancel := context.WithCancel(log.WithLog(context.Background(), logger))
	s.serviceCtx = serviceCtx
	s.serviceCancel = serviceCancel

	if err := s.reconcileTransportLink(serviceCtx); err != nil {
		s.serviceCancel()
		return err
	}

	if err := s.startWireGuard(serviceCtx); err != nil {
		s.serviceCancel()
		return err
	}

	listeners, err := s.startProxies(serviceCtx)
	if err != nil {
		_ = s.stop(ctx)
		return err
	}
	s.swapListeners(listeners)
	if s.role == "encrypt" {
		if err := s.installRedirectRules(serviceCtx); err != nil {
			_ = s.stop(ctx)
			return err
		}
	}
	s.startTransportReconciler(serviceCtx)
	if err := s.waitForWireGuardHandshake(serviceCtx); err != nil {
		_ = s.stop(ctx)
		return err
	}

	binding := s.bindingSnapshot()

	logger.Infof(
		"vpn service ready: role=%s clear=%s transport=%s outer=%s inner=%s peer_outer=%s peer_inner=%s target=%s proxy_port=%d",
		s.role,
		binding.clearLinkName,
		binding.transportLinkName,
		s.transportAddr.IPNet,
		s.innerAddr.IPNet,
		s.transportPeerIP,
		s.innerPeerIP,
		s.targetIP,
		s.proxyPort,
	)
	return nil
}

func (s *vpnService) rebind(ctx context.Context, binding vpnBinding) error {
	current := s.bindingSnapshot()
	if current.equal(binding) {
		return s.reconcileTransportLink(ctx)
	}

	oldListeners := s.swapListeners(nil)
	closeErr := closeClosers(oldListeners)
	if s.role == "encrypt" && current.clearLinkName != "" && current.clearLinkName != binding.clearLinkName {
		closeErr = errors.Join(closeErr, s.removeRedirectRulesForLink(ctx, current.clearLinkName))
	}

	s.updateBinding(binding)
	if err := s.reconcileTransportLink(ctx); err != nil {
		return errors.Join(closeErr, err)
	}
	if current.transportLinkName != "" && current.transportLinkName != binding.transportLinkName {
		if err := s.cleanupTransportLink(current.transportLinkName); err != nil {
			return errors.Join(closeErr, err)
		}
	}

	listeners, err := s.startProxies(s.serviceCtx)
	if err != nil {
		return errors.Join(closeErr, err)
	}
	if s.role == "encrypt" {
		if err := s.installRedirectRules(ctx); err != nil {
			_ = closeClosers(listeners)
			return errors.Join(closeErr, err)
		}
	}
	s.swapListeners(listeners)
	if err := s.waitForWireGuardHandshake(ctx); err != nil {
		_ = closeClosers(s.swapListeners(nil))
		return errors.Join(closeErr, err)
	}

	log.FromContext(ctx).Infof(
		"vpn service rebound: role=%s clear=%s transport=%s",
		s.role,
		binding.clearLinkName,
		binding.transportLinkName,
	)
	return closeErr
}

func (s *vpnService) startWireGuard(ctx context.Context) error {
	if existing, err := netlink.LinkByName(s.wgInterface); err == nil && existing != nil {
		_ = netlink.LinkDel(existing)
	}

	if err := runCommand(ctx, "ip", "link", "add", s.wgInterface, "type", "wireguard"); err != nil {
		log.FromContext(ctx).Warnf(
			"kernel WireGuard link creation failed for %s, falling back to wireguard-go: %v",
			s.wgInterface,
			err,
		)
		if err := s.startUserspaceWireGuard(ctx); err != nil {
			return err
		}
	}

	wgLink, err := waitForLinkByName(ctx, s.wgInterface, 5*time.Second)
	if err != nil {
		return fmt.Errorf("wait for WireGuard link %s: %w", s.wgInterface, err)
	}
	if err := netlink.AddrReplace(wgLink, s.innerAddr); err != nil {
		return fmt.Errorf("assign WireGuard address %s on %s: %w", s.innerAddr.IPNet, s.wgInterface, err)
	}
	if err := netlink.LinkSetUp(wgLink); err != nil {
		return fmt.Errorf("set WireGuard link %s up: %w", s.wgInterface, err)
	}

	args := []string{
		"set",
		s.wgInterface,
		"listen-port",
		strconv.Itoa(s.wgListenPort),
		"private-key",
		s.wgPrivateKeyPath,
		"peer",
		s.wgPeerPublicKey,
		"allowed-ips",
		s.innerPeerIP.String() + "/32",
		"endpoint",
		net.JoinHostPort(s.transportPeerIP.String(), strconv.Itoa(s.wgListenPort)),
	}
	if s.wgPersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(s.wgPersistentKeepalive))
	}
	if err := runCommand(ctx, "wg", args...); err != nil {
		return fmt.Errorf("configure WireGuard peer: %w", err)
	}
	return nil
}

func (s *vpnService) startUserspaceWireGuard(ctx context.Context) error {
	procCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, "wireguard-go", s.wgInterface)
	cmd.Env = append(os.Environ(), "WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start wireguard-go on %s: %w: %s", s.wgInterface, err, strings.TrimSpace(output.String()))
	}

	s.wgCancel = cancel
	s.wgCmd = cmd
	go func() {
		err := cmd.Wait()
		if procCtx.Err() == nil && err != nil {
			log.FromContext(ctx).Errorf("wireguard-go exited for %s: %v", s.wgInterface, err)
		}
	}()
	return nil
}

func (s *vpnService) startProxies(ctx context.Context) ([]io.Closer, error) {
	binding := s.bindingSnapshot()
	if s.role == "decrypt" {
		return startDecryptProxies(ctx, s, binding)
	}
	return startEncryptProxies(ctx, s, binding)
}

func (s *vpnService) stop(ctx context.Context) error {
	var errs []error

	if err := closeClosers(s.swapListeners(nil)); err != nil {
		errs = append(errs, err)
	}
	if s.role == "encrypt" {
		if err := s.removeRedirectRules(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if link, err := netlink.LinkByName(s.wgInterface); err == nil && link != nil {
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Errorf("delete WireGuard link %s: %w", s.wgInterface, err))
		}
	}
	if s.serviceCancel != nil {
		s.serviceCancel()
	}
	if s.wgCancel != nil {
		s.wgCancel()
	}
	if err := s.cleanupTransportLink(s.bindingSnapshot().transportLinkName); err != nil {
		errs = append(errs, err)
	}
	log.FromContext(ctx).Infof("vpn service stopped: %s", s.key)
	return errors.Join(errs...)
}

func (s *vpnService) bindingSnapshot() vpnBinding {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return vpnBinding{
		clearLinkName:     s.clearLinkName,
		transportLinkName: s.transportLinkName,
		clearSourceIP:     cloneIP(s.clearSourceIP),
	}
}

func (s *vpnService) updateBinding(binding vpnBinding) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.clearLinkName = binding.clearLinkName
	s.transportLinkName = binding.transportLinkName
	s.clearSourceIP = cloneIP(binding.clearSourceIP)
}

func (s *vpnService) swapListeners(listeners []io.Closer) []io.Closer {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	old := s.listeners
	s.listeners = listeners
	return old
}

func closeClosers(listeners []io.Closer) error {
	var errs []error
	for i := len(listeners) - 1; i >= 0; i-- {
		if err := listeners[i].Close(); err != nil && !isClosedErr(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func roleCIDRAddr(cidr, role string) (*netlink.Addr, net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	network := ipNet.IP.To4()
	if network == nil {
		return nil, nil, fmt.Errorf("only IPv4 CIDRs are supported for %s", cidr)
	}
	local := addIPv4(network, roleHostOffset(role))
	peer := addIPv4(network, rolePeerOffset(role))
	return &netlink.Addr{IPNet: &net.IPNet{IP: local, Mask: ipNet.Mask}}, peer, nil
}

func roleHostOffset(role string) uint32 {
	if role == "decrypt" {
		return 2
	}
	return 1
}

func rolePeerOffset(role string) uint32 {
	if role == "decrypt" {
		return 1
	}
	return 2
}

func addIPv4(ip net.IP, delta uint32) net.IP {
	base := ip.To4()
	if base == nil {
		return nil
	}
	value := binary.BigEndian.Uint32(base)
	value += delta
	result := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(result, value)
	return result
}

func firstIPv4(link netlink.Link) (net.IP, error) {
	if link == nil {
		return nil, nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}
	return nil, nil
}

func resolveClearSourceIP(sessionCtx *SessionContext, clearLink netlink.Link) (net.IP, error) {
	ip, err := firstIPv4(clearLink)
	if err != nil {
		return nil, err
	}
	if ip != nil {
		return ip, nil
	}
	if ip = connectionSourceIPv4(sessionCtx.UpstreamConnection()); ip != nil {
		return ip, nil
	}
	if ip = connectionSourceIPv4(sessionCtx.DownstreamConnection()); ip != nil {
		return ip, nil
	}
	return nil, nil
}

func connectionSourceIPv4(conn *networkservice.Connection) net.IP {
	if conn == nil || conn.GetContext() == nil || conn.GetContext().GetIpContext() == nil {
		return nil
	}
	for _, cidr := range conn.GetContext().GetIpContext().GetSrcIpAddrs() {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4
		}
	}
	return nil
}

func (s *vpnService) startTransportReconciler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.reconcileTransportLink(ctx); err != nil && ctx.Err() == nil {
					log.FromContext(ctx).Warnf(
						"transport link reconcile failed on %s: %v",
						s.bindingSnapshot().transportLinkName,
						err,
					)
				}
			}
		}
	}()
}

func (s *vpnService) reconcileTransportLink(ctx context.Context) error {
	binding := s.bindingSnapshot()
	transportLink, err := netlink.LinkByName(binding.transportLinkName)
	if err != nil {
		return fmt.Errorf("lookup transport link %s: %w", binding.transportLinkName, err)
	}
	transportRoute, err := normalizedIPv4Net(s.transportAddr.IPNet)
	if err != nil {
		return fmt.Errorf("normalize transport route for %s: %w", s.transportAddr.IPNet, err)
	}
	if err := netlink.LinkSetUp(transportLink); err != nil {
		return fmt.Errorf("set transport link %s up: %w", binding.transportLinkName, err)
	}
	if err := deleteUnexpectedIPv4Routes(transportLink, transportRoute); err != nil {
		return fmt.Errorf("cleanup transport routes on %s: %w", binding.transportLinkName, err)
	}
	if err := deleteUnexpectedIPv4Addrs(transportLink, s.transportAddr); err != nil {
		return fmt.Errorf("cleanup transport addresses on %s: %w", binding.transportLinkName, err)
	}
	if err := netlink.AddrReplace(transportLink, s.transportAddr); err != nil {
		return fmt.Errorf("assign transport address %s on %s: %w", s.transportAddr.IPNet, binding.transportLinkName, err)
	}
	if err := ensureIPv4LinkRoute(transportLink, transportRoute); err != nil {
		return fmt.Errorf("ensure transport route %s on %s: %w", transportRoute, binding.transportLinkName, err)
	}
	return nil
}

func (s *vpnService) cleanupTransportLink(linkName string) error {
	if linkName == "" {
		return nil
	}
	transportLink, err := netlink.LinkByName(linkName)
	if err != nil {
		if isLinkNotFoundErr(err) {
			return nil
		}
		return fmt.Errorf("lookup transport link %s: %w", linkName, err)
	}
	transportRoute, err := normalizedIPv4Net(s.transportAddr.IPNet)
	if err != nil {
		return fmt.Errorf("normalize transport route for %s: %w", s.transportAddr.IPNet, err)
	}
	if err := netlink.RouteDel(&netlink.Route{
		LinkIndex: transportLink.Attrs().Index,
		Dst:       transportRoute,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("remove transport route %s from %s: %w", transportRoute, linkName, err)
	}
	if err := netlink.AddrDel(transportLink, s.transportAddr); err != nil && !strings.Contains(err.Error(), "cannot assign requested address") {
		return fmt.Errorf("remove transport address %s from %s: %w", s.transportAddr.IPNet, linkName, err)
	}
	return nil
}

func deleteUnexpectedIPv4Addrs(link netlink.Link, keep *netlink.Addr) error {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if addrMatches(&addr, keep) {
			continue
		}
		if err := netlink.AddrDel(link, &addr); err != nil && !strings.Contains(err.Error(), "cannot assign requested address") {
			return err
		}
	}
	return nil
}

func deleteUnexpectedIPv4Routes(link netlink.Link, keep *net.IPNet) error {
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.LinkIndex != link.Attrs().Index {
			continue
		}
		if routeMatches(route, keep) {
			continue
		}
		if err := netlink.RouteDel(&route); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	return nil
}

func addrMatches(addr *netlink.Addr, keep *netlink.Addr) bool {
	if addr == nil || keep == nil || addr.IPNet == nil || keep.IPNet == nil {
		return false
	}
	return addr.IPNet.IP.Equal(keep.IPNet.IP) && bytes.Equal(addr.IPNet.Mask, keep.IPNet.Mask)
}

func routeMatches(route netlink.Route, keep *net.IPNet) bool {
	if keep == nil {
		return false
	}
	if route.Dst == nil {
		return false
	}
	return route.Dst.IP.Equal(keep.IP) && bytes.Equal(route.Dst.Mask, keep.Mask)
}

func ensureIPv4LinkRoute(link netlink.Link, dst *net.IPNet) error {
	if link == nil || dst == nil {
		return fmt.Errorf("link and destination are required")
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Scope:     netlink.SCOPE_LINK,
	})
}

func normalizedIPv4Net(ipNet *net.IPNet) (*net.IPNet, error) {
	if ipNet == nil {
		return nil, fmt.Errorf("ip network is required")
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDRs are supported")
	}
	mask := ipNet.Mask
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}

func waitForLinkByName(ctx context.Context, name string, timeout time.Duration) (netlink.Link, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		link, err := netlink.LinkByName(name)
		if err == nil {
			return link, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("lookup link %s: %w", name, lastErr)
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func ipEqual(left, right net.IP) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return left.Equal(right)
	}
}

func readTrimmedFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("file %s is empty", path)
	}
	return value, nil
}

func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf(
			"%s %s failed: %w stdout=%q stderr=%q",
			name,
			strings.Join(args, " "),
			err,
			strings.TrimSpace(stdout.String()),
			strings.TrimSpace(stderr.String()),
		)
	}
	return nil
}

func (s *vpnService) waitForWireGuardHandshake(ctx context.Context) error {
	deadline := time.Now().Add(wireGuardReadyTimeout)
	var lastState string

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		ready, state, err := s.hasWireGuardHandshake(ctx)
		if err == nil && ready {
			log.FromContext(ctx).Infof(
				"WireGuard handshake established on %s with peer %s",
				s.wgInterface,
				state,
			)
			return nil
		}
		if err != nil {
			lastState = err.Error()
		} else {
			lastState = state
		}
		time.Sleep(200 * time.Millisecond)
	}

	if lastState == "" {
		lastState = "no handshake observed"
	}
	return fmt.Errorf("wait for WireGuard handshake on %s: %s", s.wgInterface, lastState)
}

func (s *vpnService) hasWireGuardHandshake(ctx context.Context) (bool, string, error) {
	cmd := exec.CommandContext(ctx, "wg", "show", s.wgInterface, "latest-handshakes")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", fmt.Errorf("wg show %s latest-handshakes failed: %w: %s", s.wgInterface, err, strings.TrimSpace(string(output)))
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if err != nil {
			return false, "", fmt.Errorf("parse latest handshake %q: %w", line, err)
		}
		if ts > 0 {
			return true, fields[0], nil
		}
		return false, "latest-handshake=0", nil
	}

	return false, "no peer state", nil
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) || strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}

func isLinkNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "link not found")
}

func (s *vpnService) installRedirectRules(ctx context.Context) error {
	if s.clearLinkName == "" {
		return fmt.Errorf("clear-side interface is required for redirect rules")
	}
	port := strconv.Itoa(s.proxyPort)
	for _, proto := range []string{"tcp", "udp"} {
		if err := ensureRedirectRule(ctx, s.clearLinkName, proto, port, "nse-ovs-vpn-encrypt-"+proto); err != nil {
			return err
		}
	}
	return nil
}

func (s *vpnService) removeRedirectRules(ctx context.Context) error {
	return s.removeRedirectRulesForLink(ctx, s.clearLinkName)
}

func (s *vpnService) removeRedirectRulesForLink(ctx context.Context, linkName string) error {
	if linkName == "" {
		return nil
	}
	port := strconv.Itoa(s.proxyPort)
	var errs []error
	for _, proto := range []string{"tcp", "udp"} {
		if err := deleteRedirectRule(ctx, linkName, proto, port, "nse-ovs-vpn-encrypt-"+proto); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
