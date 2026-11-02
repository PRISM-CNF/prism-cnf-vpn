package vnf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

type tcpDialFunc func(context.Context) (net.Conn, error)
type udpDialFunc func(context.Context) (*net.UDPConn, error)

func startEncryptProxies(ctx context.Context, svc *vpnService, binding vpnBinding) ([]io.Closer, error) {
	tcpListener, err := startTCPProxyWithFallback(ctx, binding.clearSourceIP, svc.proxyPort, func(proxyCtx context.Context) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(proxyCtx, "tcp4", net.JoinHostPort(svc.innerPeerIP.String(), strconv.Itoa(svc.proxyPort)))
	})
	if err != nil {
		return nil, err
	}

	udpProxy, err := startUDPProxyWithFallback(ctx, binding.clearSourceIP, svc.proxyPort, func(context.Context) (*net.UDPConn, error) {
		return net.DialUDP("udp4", nil, &net.UDPAddr{IP: svc.innerPeerIP, Port: svc.proxyPort})
	})
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	return []io.Closer{tcpListener, udpProxy}, nil
}

func startDecryptProxies(ctx context.Context, svc *vpnService, binding vpnBinding) ([]io.Closer, error) {
	tcpListener, err := startTCPProxy(ctx, (&net.TCPAddr{IP: svc.innerLocalIP, Port: svc.proxyPort}).String(), func(proxyCtx context.Context) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
			Control: bindToDeviceControl(binding.clearLinkName),
		}
		if binding.clearSourceIP != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: binding.clearSourceIP}
		}
		return dialer.DialContext(proxyCtx, "tcp4", net.JoinHostPort(svc.targetIP.String(), strconv.Itoa(svc.proxyPort)))
	})
	if err != nil {
		return nil, err
	}

	udpProxy, err := startUDPProxy(ctx, &net.UDPAddr{IP: svc.innerLocalIP, Port: svc.proxyPort}, func(context.Context) (*net.UDPConn, error) {
		var localAddr *net.UDPAddr
		if binding.clearSourceIP != nil {
			localAddr = &net.UDPAddr{IP: binding.clearSourceIP}
		}
		dialer := &net.Dialer{
			LocalAddr: localAddr,
			Control:   bindToDeviceControl(binding.clearLinkName),
		}
		conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(svc.targetIP.String(), strconv.Itoa(svc.proxyPort)))
		if err != nil {
			return nil, err
		}
		udpConn, ok := conn.(*net.UDPConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("expected UDP connection, got %T", conn)
		}
		return udpConn, nil
	})
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	return []io.Closer{tcpListener, udpProxy}, nil
}

func startTCPProxy(ctx context.Context, listenAddr string, dial tcpDialFunc) (net.Listener, error) {
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
	logger := log.FromContext(ctx)
	go func() {
		for {
			clientConn, err := listener.Accept()
			if err != nil {
				if isClosedErr(err) {
					return
				}
				logger.Errorf("tcp proxy accept failed on %s: %v", listenAddr, err)
				continue
			}
			logger.Infof("tcp proxy accepted on %s from %s", listenAddr, clientConn.RemoteAddr())
			go handleTCPProxyConn(ctx, listenAddr, clientConn, dial)
		}
	}()
	return listener, nil
}

func startTCPProxyWithFallback(ctx context.Context, listenIP net.IP, port int, dial tcpDialFunc) (net.Listener, error) {
	listenAddr := &net.TCPAddr{Port: port}
	if listenIP != nil {
		listenAddr.IP = listenIP
	}

	listener, err := startTCPProxy(ctx, listenAddr.String(), dial)
	if err == nil || listenIP == nil {
		return listener, err
	}

	log.FromContext(ctx).Warnf(
		"tcp proxy listen on %s failed, falling back to wildcard bind: %v",
		listenAddr.String(),
		err,
	)

	return startTCPProxy(ctx, (&net.TCPAddr{Port: port}).String(), dial)
}

func handleTCPProxyConn(ctx context.Context, listenAddr string, clientConn net.Conn, dial tcpDialFunc) {
	logger := log.FromContext(ctx)
	upstreamConn, err := dial(ctx)
	if err != nil {
		logger.Errorf("tcp proxy dial failed: %v", err)
		_ = clientConn.Close()
		return
	}
	logger.Infof(
		"tcp proxy connected on %s client=%s upstream=%s",
		listenAddr,
		clientConn.RemoteAddr(),
		upstreamConn.RemoteAddr(),
	)
	relayTCP(clientConn, upstreamConn)
}

func relayTCP(left, right net.Conn) {
	var wg sync.WaitGroup
	copyOne := func(dst net.Conn, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tcpConn, ok := dst.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}

	wg.Add(2)
	go copyOne(left, right)
	go copyOne(right, left)
	wg.Wait()
	_ = left.Close()
	_ = right.Close()
}

type udpProxy struct {
	ctx      context.Context
	listener *net.UDPConn
	dial     udpDialFunc

	mu    sync.Mutex
	peers map[string]*udpPeer
}

type udpPeer struct {
	sourceAddr *net.UDPAddr
	upstream   *net.UDPConn
}

func startUDPProxy(ctx context.Context, listenAddr *net.UDPAddr, dial udpDialFunc) (io.Closer, error) {
	listener, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp on %s: %w", listenAddr, err)
	}
	proxy := &udpProxy{
		ctx:      ctx,
		listener: listener,
		dial:     dial,
		peers:    map[string]*udpPeer{},
	}
	go proxy.serve()
	return proxy, nil
}

func startUDPProxyWithFallback(ctx context.Context, listenIP net.IP, port int, dial udpDialFunc) (io.Closer, error) {
	listenAddr := &net.UDPAddr{Port: port}
	if listenIP != nil {
		listenAddr.IP = listenIP
	}

	proxy, err := startUDPProxy(ctx, listenAddr, dial)
	if err == nil || listenIP == nil {
		return proxy, err
	}

	log.FromContext(ctx).Warnf(
		"udp proxy listen on %s failed, falling back to wildcard bind: %v",
		listenAddr.String(),
		err,
	)

	return startUDPProxy(ctx, &net.UDPAddr{Port: port}, dial)
}

func (p *udpProxy) serve() {
	logger := log.FromContext(p.ctx)
	buffer := make([]byte, 64*1024)
	for {
		bytesRead, sourceAddr, err := p.listener.ReadFromUDP(buffer)
		if err != nil {
			if isClosedErr(err) {
				return
			}
			logger.Errorf("udp proxy read failed: %v", err)
			continue
		}
		peer, err := p.ensurePeer(sourceAddr)
		if err != nil {
			logger.Errorf("udp proxy upstream setup failed for %s: %v", sourceAddr, err)
			continue
		}
		if _, err := peer.upstream.Write(buffer[:bytesRead]); err != nil {
			logger.Errorf("udp proxy write failed for %s: %v", sourceAddr, err)
		}
	}
}

func (p *udpProxy) ensurePeer(sourceAddr *net.UDPAddr) (*udpPeer, error) {
	key := sourceAddr.String()

	p.mu.Lock()
	if peer, ok := p.peers[key]; ok {
		p.mu.Unlock()
		return peer, nil
	}
	p.mu.Unlock()

	upstream, err := p.dial(p.ctx)
	if err != nil {
		return nil, err
	}

	peer := &udpPeer{
		sourceAddr: cloneUDPAddr(sourceAddr),
		upstream:   upstream,
	}

	p.mu.Lock()
	if existing, ok := p.peers[key]; ok {
		p.mu.Unlock()
		_ = upstream.Close()
		return existing, nil
	}
	p.peers[key] = peer
	p.mu.Unlock()

	go p.copyBack(key, peer)
	return peer, nil
}

func (p *udpProxy) copyBack(key string, peer *udpPeer) {
	logger := log.FromContext(p.ctx)
	buffer := make([]byte, 64*1024)
	for {
		bytesRead, err := peer.upstream.Read(buffer)
		if err != nil {
			if !isClosedErr(err) {
				logger.Errorf("udp proxy upstream read failed for %s: %v", key, err)
			}
			break
		}
		if _, err := p.listener.WriteToUDP(buffer[:bytesRead], peer.sourceAddr); err != nil {
			if !isClosedErr(err) {
				logger.Errorf("udp proxy downstream write failed for %s: %v", key, err)
			}
			break
		}
	}

	p.mu.Lock()
	delete(p.peers, key)
	p.mu.Unlock()
	_ = peer.upstream.Close()
}

func (p *udpProxy) Close() error {
	var errs []error
	if err := p.listener.Close(); err != nil && !isClosedErr(err) {
		errs = append(errs, err)
	}

	p.mu.Lock()
	peers := make([]*udpPeer, 0, len(p.peers))
	for _, peer := range p.peers {
		peers = append(peers, peer)
	}
	p.peers = map[string]*udpPeer{}
	p.mu.Unlock()

	for _, peer := range peers {
		if err := peer.upstream.Close(); err != nil && !isClosedErr(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	cloned := *addr
	if addr.IP != nil {
		cloned.IP = append(net.IP(nil), addr.IP...)
	}
	return &cloned
}

func bindToDeviceControl(device string) func(string, string, syscall.RawConn) error {
	if device == "" {
		return nil
	}
	return func(_, _ string, rawConn syscall.RawConn) error {
		var controlErr error
		if err := rawConn.Control(func(fd uintptr) {
			controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		if controlErr != nil {
			return fmt.Errorf("bind socket to device %s: %w", device, controlErr)
		}
		return nil
	}
}
