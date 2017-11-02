// Package protected is used for creating "protected" connections
// that bypass Android's VpnService
package protected

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
	"github.com/getlantern/ops"
)

var (
	log              = golog.LoggerFor("lantern-android.protected")
	defaultDNSServer = "8.8.8.8"
	dnsPort          = 53
)

const (
	defaultDialTimeout = 1 * time.Minute
	readDeadline       = 15 * time.Second
	writeDeadline      = 15 * time.Second
	socketError        = -1
)

// Protect is the actual function to protect a connection. Same signature as
// https://developer.android.com/reference/android/net/VpnService.html#protect(java.net.Socket)
type Protect func(fileDescriptor int) error

type Protector struct {
	protect Protect
	dnsAddr syscall.Sockaddr
}

type protectedAddr struct {
	IP   net.IP
	Port int
	Zone string // IPv6 scoped addressing zone
}

func (addr *protectedAddr) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: addr.IP, Port: addr.Port}
}

func (addr *protectedAddr) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{IP: addr.IP, Port: addr.Port}
}

// New construct a protector from the protect function and DNS server IP address.
func New(protect Protect, dnsServer string) *Protector {
	var ipAddr net.IP
	host, port, err := splitHostPort(dnsServer)
	if err != nil {
		log.Errorf("Invalid DNS server address %s: %v", dnsServer, err)
	} else {
		ipAddr = net.ParseIP(host)
	}
	if ipAddr == nil {
		log.Debugf("Using default DNS server: %v", defaultDNSServer)
		ipAddr = net.ParseIP(defaultDNSServer)
		port = dnsPort
	}
	log.Debugf("Using dns server %v:%v", ipAddr, port)
	dnsAddr := syscall.SockaddrInet4{Port: port}
	copy(dnsAddr.Addr[:], ipAddr.To4())
	return &Protector{protect, &dnsAddr}
}

// ResolveTCP resolves the given TCP address using a DNS lookup on a UDP socket
// protected by the given Protect function.
func (p *Protector) ResolveTCP(network string, addr string) (*net.TCPAddr, error) {
	op := ops.Begin("protected-resolve").Set("addr", addr)
	defer op.End()

	switch network {
	case "tcp", "tcp4", "tcp6":
		break
	case "":
		network = "tcp"
	default:
		return nil, op.FailIf(log.Errorf("Resolve: Unsupported network: %s", network))
	}
	resolved, err := p.resolve(network, addr)
	if err != nil {
		return nil, op.FailIf(err)
	}
	return resolved.TCPAddr(), nil
}

// ResolveUDP resolves the given UDP address using a DNS lookup on a UDP socket
// protected by the given Protect function.
func (p *Protector) ResolveUDP(network, addr string) (*net.UDPAddr, error) {
	op := ops.Begin("protected-resolve").Set("addr", addr)
	defer op.End()

	switch network {
	case "udp", "udp4", "udp6":
		break
	default:
		return nil, op.FailIf(log.Errorf("ResolveUDP: Unsupported network: %s", network))
	}
	resolved, err := p.resolve(network, addr)
	if err != nil {
		return nil, op.FailIf(err)
	}
	return resolved.UDPAddr(), nil
}

func (p *Protector) resolve(network string, addr string) (*protectedAddr, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}

	getProtectedAddr := func(network string, IP net.IP, port int) (*protectedAddr, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		case "udp", "udp4", "udp6":
			break
		default:
			return nil, errors.New("Unsupported network: %v", network)
		}
		return &protectedAddr{IP: IP, Port: port}, nil
	}

	// Check if we already have the IP address
	IPAddr := net.ParseIP(host)
	if IPAddr != nil {
		return getProtectedAddr(network, IPAddr, port)
	}

	// Create a datagram socket
	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, errors.New("Error creating socket: %v", err)
	}
	defer syscall.Close(socketFd)

	// Here we protect the underlying socket from the
	// VPN connection by passing the file descriptor
	// back to Java for exclusion
	err = p.protect(socketFd)
	if err != nil {
		return nil, errors.New("Could not bind socket to system device: %v", err)
	}

	err = syscall.Connect(socketFd, p.dnsAddr)
	if err != nil {
		return nil, errors.New("Unable to call syscall.Connect: %v", err)
	}

	fd := uintptr(socketFd)
	file := os.NewFile(fd, "")
	defer file.Close()

	// return a copy of the network connection
	// represented by file
	fileConn, err := net.FileConn(file)
	if err != nil {
		return nil, errors.New("Error returning a copy of the network connection: %v", err)
	}

	setQueryTimeouts(fileConn)

	log.Debugf("lookup %s via %v", host, p.dnsAddr)
	result, err := dnsLookup(host, fileConn)
	if err != nil {
		return nil, errors.New("Error doing DNS resolution: %v", err)
	}
	ipAddr, err := result.PickRandomIP()
	if err != nil {
		return nil, errors.New("No IP address available: %v", err)
	}
	return getProtectedAddr(network, ipAddr, port)
}

// Dial creates a new protected connection.
// - syscall API calls are used to create and bind to the
//   specified system device (this is primarily
//   used for Android VpnService routing functionality)
func (p *Protector) Dial(network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
	defer cancel()
	return p.DialContext(ctx, network, addr)
}

func (p *Protector) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return p.DialContext(ctx, network, addr)
}

// DialContext is same as Dial, but accepts a context instead of timeout value.
func (p *Protector) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	op := ops.Begin("protected-dial").Set("addr", addr)
	dl, ok := ctx.Deadline()
	if ok {
		op.Set("timeout", dl.Sub(time.Now()).Seconds())
	}
	defer op.End()

	// Dial in goroutine to support arbitrary cancellation.
	var conn net.Conn
	var err error
	chDone := make(chan bool)
	go func() {
		conn, err = p.dialContext(op, ctx, network, addr)
		if err != nil {
			log.Errorf("Could not dial %s %s: %v", network, addr, err)
		}
		select {
		case chDone <- true:
		default:
			if conn != nil {
				conn.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, op.FailIf(ctx.Err())
	case <-chDone:
		return conn, op.FailIf(err)
	}
}

func (p *Protector) DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	op := ops.Begin("protected-dial-udp").Set("addr", raddr.String())
	defer op.End()
	switch network {
	case "udp", "udp4", "udp6":
		// verify we have a udp network
		break
	default:
		return nil, op.FailIf(log.Errorf("Unable to dial %v ; unsupported network: %v", raddr, network))
	}
	// Try to resolve it
	conn, err := p.Dial(network, raddr.String())
	if err != nil {
		return nil, op.FailIf(err)
	}
	return conn.(*net.UDPConn), nil
}

// dialContext checks if context has been done between each phase to avoid
// unnecessary work, but doesn't support arbitrary cancellation.
func (p *Protector) dialContext(op ops.Op, ctx context.Context, network, addr string) (net.Conn, error) {
	var socketType int
	switch network {
	case "tcp", "tcp4", "tcp6":
		socketType = syscall.SOCK_STREAM
	case "udp", "udp4", "udp6":
		socketType = syscall.SOCK_DGRAM
	default:
		err := errors.New("Unsupported network: %v", network)
		log.Error(err)
		return nil, err
	}

	// Try to resolve it
	raddr, err := p.resolve(network, addr)
	if err != nil {
		return nil, op.FailIf(err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// continue
	}

	sockAddr := syscall.SockaddrInet4{Port: raddr.Port}
	copy(sockAddr.Addr[:], raddr.IP.To4())
	socketFd, err := syscall.Socket(syscall.AF_INET, socketType, 0)
	if err != nil {
		return nil, errors.New("Could not create socket: %v", err)
	}
	conn := &protectedConn{sockAddr: &sockAddr, socketFd: socketFd}
	defer conn.cleanup()

	// Actually protect the underlying socket here
	err = p.protect(conn.socketFd)
	if err != nil {
		err = errors.New("Unable to protect socket to %v with fd %v and network %v: %v",
			addr, conn.socketFd, network, err)
		log.Error(err)
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// continue
	}

	err = conn.connectSocket(ctx)
	if err != nil {
		return nil, errors.New("Unable to connect socket to %v: %v", addr, err)
	}

	// finally, convert the socket fd to a net.Conn
	err = conn.convert()
	if err != nil {
		return nil, errors.New("Error converting protected connection: %v", err)
	}
	return conn.Conn, nil
}

type protectedConn struct {
	net.Conn
	mutex    sync.Mutex
	isClosed bool
	socketFd int
	sockAddr syscall.Sockaddr
}

// connectSocket makes the connection to the given IP address port
// for the given socket fd
func (conn *protectedConn) connectSocket(ctx context.Context) error {
	errCh := make(chan error)
	go func() {
		errCh <- syscall.Connect(conn.socketFd, conn.sockAddr)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// converts the protected connection specified by
// socket fd to a net.Conn
func (conn *protectedConn) convert() error {
	conn.mutex.Lock()
	file := os.NewFile(uintptr(conn.socketFd), "")
	// dup the fd and return a copy
	fileConn, err := net.FileConn(file)
	// closes the original fd
	file.Close()
	conn.socketFd = socketError
	if err != nil {
		conn.mutex.Unlock()
		return err
	}
	conn.Conn = fileConn
	conn.mutex.Unlock()
	return nil
}

// cleanup is run whenever we encounter a socket error
// we use a mutex since this connection is active in a variety
// of goroutines and to prevent any possible race conditions
func (conn *protectedConn) cleanup() {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.socketFd != socketError {
		syscall.Close(conn.socketFd)
		conn.socketFd = socketError
	}
}

// Close is used to destroy a protected connection
func (conn *protectedConn) Close() (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.isClosed {
		conn.isClosed = true
		if conn.Conn == nil {
			if conn.socketFd == socketError {
				err = nil
			} else {
				err = syscall.Close(conn.socketFd)
				// update socket fd to socketError
				// to make it explicit this connection
				// has been closed
				conn.socketFd = socketError
			}
		} else {
			err = conn.Conn.Close()
		}
	}
	return err
}

// configure DNS query expiration
func setQueryTimeouts(c net.Conn) {
	now := time.Now()
	c.SetReadDeadline(now.Add(readDeadline))
	c.SetWriteDeadline(now.Add(writeDeadline))
}

// splitHostAndPort is a wrapper around net.SplitHostPort that also uses strconv
// to convert the port to an int
func splitHostPort(addr string) (string, int, error) {
	host, sPort, err := net.SplitHostPort(addr)
	if err != nil {
		log.Errorf("Could not split network address: %v", err)
		return "", 0, errors.Wrap(err)
	}
	port, err := strconv.Atoi(sPort)
	if err != nil {
		log.Errorf("No port number found %v", err)
		return "", 0, errors.Wrap(err)
	}
	return host, port, nil
}
