package protected

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/getlantern/golog"
	"github.com/stretchr/testify/assert"
)

const (
	testAddr = "www.google.com:443"
)

type testprotector struct {
	lastProtected int
}

func (p *testprotector) Protect(fileDescriptor int) error {
	p.lastProtected = fileDescriptor
	return nil
}

func TestConnectIPv4(t *testing.T) {
	doTestConnectIP(t, "8.8.8.8")
}

func TestConnectIPv6(t *testing.T) {
	dnsServer := "2001:4860:4860::8888"
	conn, err := net.Dial("udp6", fmt.Sprintf("[%v]:53", dnsServer))
	if err != nil {
		log.Debugf("Unable to dial IPv6 DNS server, assuming IPv6 not supported on this network: %v", err)
		return
	}
	conn.Close()
	doTestConnectIP(t, dnsServer)
}

func doTestConnectIP(t *testing.T, dnsServer string) {
	p := &testprotector{}
	pt := New(p.Protect, func() string { return dnsServer })
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				_resolved, err := pt.resolve("tcp", addr)
				if err != nil {
					return nil, err
				}
				resolved := _resolved.TCPAddr()
				return pt.Dial(netw, resolved.String())
			},
			ResponseHeaderTimeout: time.Second * 2,
		},
	}
	err := sendTestRequest(client, testAddr)
	if assert.NoError(t, err, "Request should have succeeded") {
		assert.NotEqual(t, 0, p.lastProtected, "Should have gotten file descriptor from protecting")
	}
}

func TestConnectHost(t *testing.T) {
	p := &testprotector{}
	pt := New(p.Protect, func() string { return "8.8.8.8" })
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				return pt.Dial(netw, addr)
			},
			ResponseHeaderTimeout: time.Second * 2,
		},
	}
	err := sendTestRequest(client, testAddr)
	if assert.NoError(t, err, "Request should have succeeded") {
		assert.NotEqual(t, 0, p.lastProtected, "Should have gotten file descriptor from protecting")
	}
}

func TestDialUDP(t *testing.T) {
	l, err := net.ListenPacket("udp4", "127.0.0.1:53243")
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()
	go func() {
		b := make([]byte, 4)
		_, addr, err := l.ReadFrom(b)
		if !assert.NoError(t, err) {
			return
		}
		l.WriteTo(b, addr)
	}()

	p := &testprotector{}
	pt := New(p.Protect, func() string { return "8.8.8.8" })
	conn, err := pt.Dial("udp", l.LocalAddr().String())
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("echo"))
	if !assert.NoError(t, err) {
		return
	}
	b := make([]byte, 4)
	_, err = conn.Read(b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "echo", string(b))
	assert.NotEqual(t, 0, p.lastProtected, "Should have gotten file descriptor from protecting")
}

func TestListenUDP(t *testing.T) {
	l, err := net.ListenPacket("udp4", ":53243")
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()
	go func() {
		b := make([]byte, 4)
		_, addr, err := l.ReadFrom(b)
		if !assert.NoError(t, err) {
			return
		}
		l.WriteTo(b, addr)
	}()

	p := &testprotector{}
	pt := New(p.Protect, func() string { return "8.8.8.8" })

	conn, err := pt.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	_, err = conn.WriteTo([]byte("echo"), l.LocalAddr())
	if !assert.NoError(t, err) {
		return
	}
	b := make([]byte, 4)
	_, _, err = conn.ReadFrom(b)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "echo", string(b))
	assert.NotEqual(t, 0, p.lastProtected, "Should have gotten file descriptor from protecting")
}

func sendTestRequest(client *http.Client, addr string) error {
	log := golog.LoggerFor("protected")

	req, err := http.NewRequest("GET", "https://"+addr+"/humans.txt", nil)
	if err != nil {
		return fmt.Errorf("Error constructing new HTTP request: %s", err)
	}
	req.Header.Add("Connection", "keep-alive")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Could not make request to %s: %s", addr, err)
	}
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading response body: %s", err)
	}
	resp.Body.Close()
	log.Debugf("Successfully processed request to %s", addr)
	return nil
}

func TestNoZone(t *testing.T) {
	assert.Equal(t, "68.105.28.11", noZone("[68.105.28.11]"))
	assert.Equal(t, "2001:4860:4860::8888", noZone("2001:4860:4860::8888"))
	assert.Equal(t, "2001:4860:4860::8888", noZone("[2001:4860:4860::8888]"))
	assert.Equal(t, "2001:4860:4860::8888", noZone("2001:4860:4860::8888%wlan0"))
	assert.Equal(t, "2001:4860:4860::8888", noZone("[2001:4860:4860::8888%wlan0]"))
}
