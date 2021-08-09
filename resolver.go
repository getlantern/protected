package protected

import (
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/getlantern/errors"
)

// dnsLookup is used whenever we need to conduct a DNS query over a given TCP connection
func dnsLookup(addr string, conn net.Conn, isIPv6 bool) ([]net.IP, error) {
	// create the connection to the DNS server
	dnsConn := &dns.Conn{Conn: conn}
	defer dnsConn.Close()

	query := func(t uint16) {
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.SetQuestion(dns.Fqdn(addr), t)
		m.RecursionDesired = true
		dnsConn.WriteMsg(m)
	}

	v4IPs := make(chan []net.IP, 1)
	v6IPs := make(chan []net.IP, 1)
	errCh := make(chan error, 1)

	readResponse := func() {
		ips := make([]net.IP, 0)

		response, err := dnsConn.ReadMsg()
		if err != nil {
			errCh <- errors.Wrap(err)
			return
		}

		isIPv6 := false

		// iterate over RRs containing the DNS answer
		for _, answer := range response.Answer {
			if a, ok := answer.(*dns.A); ok {
				ips = append(ips, a.A)
			} else if a, ok := answer.(*dns.AAAA); ok {
				isIPv6 = true
				ips = append(ips, a.AAAA)
			}
		}

		if isIPv6 {
			v6IPs <- ips
		} else {
			v4IPs <- ips
		}
	}

	query(dns.TypeA)
	go readResponse()
	if isIPv6 {
		// also query for AAAA record
		query(dns.TypeAAAA)
		go readResponse()
	}

	select {
	case ipsV4 := <-v4IPs:
		if !isIPv6 {
			return ipsV4, nil
		} else {
			select {
			case ipsV6 := <-v6IPs:
				return ipsV6, nil
			case <-time.After(dnsAdditionalResponseTimeout):
				// if we don't get an IPv6 response, just use the IPv4 response
				return ipsV4, nil
			}
		}
	case ipsV6 := <-v6IPs:
		return ipsV6, nil
	case err := <-errCh:
		// we just return the first error since this is almost certainly a timeout, so if one
		// query timed out the other parallel query will too
		return nil, err
	}

}
