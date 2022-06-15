// This file has been adapted from https://github.com/norouter/norouter/blob/v0.6.4/pkg/agent/dns/dns.go

package dns

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Truncate for avoiding "Parse error" from `busybox nslookup`
// https://github.com/lima-vm/lima/issues/380
const truncateSize = 512

var defaultFallbackIPs = []string{"8.8.8.8", "1.1.1.1"}

type ServerOptions struct {
	Address         string
	TCPPort         int
	UDPPort         int
	IPv6            bool
	StaticHosts     map[string]string
	UpstreamServers []string
	TruncateReply   bool
}

type Handler struct {
	truncate     bool
	clientConfig *dns.ClientConfig
	clients      []*dns.Client
	ipv6         bool
	cnameToHost  map[string]string
	hostToIP     map[string]net.IP
}

type Server struct {
	udp *dns.Server
	tcp *dns.Server
}

func NewHandler(opts *ServerOptions) (dns.Handler, error) {
	var cc *dns.ClientConfig
	var err error
	if len(opts.UpstreamServers) == 0 {
		if runtime.GOOS != "windows" {
			cc, err = dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				logrus.WithError(err).Warnf("failed to detect system DNS, falling back to %v", defaultFallbackIPs)
				cc, err = newStaticClientConfig(defaultFallbackIPs)
				if err != nil {
					return nil, err
				}
			}
		} else {
			// For windows, the only fallback addresses are defaultFallbackIPs
			// since there is no /etc/resolv.conf
			cc, err = newStaticClientConfig(defaultFallbackIPs)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if cc, err = newStaticClientConfig(opts.UpstreamServers); err != nil {
			if cc, err = newStaticClientConfig(defaultFallbackIPs); err != nil {
				return nil, err
			}
		}
	}

	clients := []*dns.Client{
		{}, // UDP
		{Net: "tcp"},
	}
	h := &Handler{
		truncate:     opts.TruncateReply,
		clientConfig: cc,
		clients:      clients,
		ipv6:         opts.IPv6,
		cnameToHost:  make(map[string]string),
		hostToIP:     make(map[string]net.IP),
	}
	for host, address := range opts.StaticHosts {
		if ip := net.ParseIP(address); ip != nil {
			h.hostToIP[Cname(host)] = ip
		} else {
			h.cnameToHost[Cname(host)] = Cname(address)
		}
	}
	return h, nil
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	switch req.Opcode {
	case dns.OpcodeQuery:
		h.handleQuery(w, req)
	default:
		h.handleDefault(w, req)
	}
}

func Start(opts *ServerOptions) (*Server, error) {
	server := &Server{}
	if opts.UDPPort > 0 {
		udpOptions := opts
		// always enable reply truncate for UDP
		udpOptions.TruncateReply = true
		h, err := NewHandler(udpOptions)
		if err != nil {
			return nil, err
		}
		addr := fmt.Sprintf("%s:%d", opts.Address, opts.UDPPort)
		s := &dns.Server{Net: "udp", Addr: addr, Handler: h}
		server.udp = s
		go func() {
			logrus.Debugf("Start UDP server listening on: %v", addr)
			if e := s.ListenAndServe(); e != nil {
				panic(e)
			}
		}()
	}
	if opts.TCPPort > 0 {
		tcpOpts := opts
		tcpOpts.TruncateReply = false
		h, err := NewHandler(tcpOpts)
		if err != nil {
			return nil, err
		}
		addr := fmt.Sprintf("%s:%d", opts.Address, opts.TCPPort)
		s := &dns.Server{Net: "tcp", Addr: addr, Handler: h}
		server.tcp = s
		go func() {
			logrus.Debugf("Start TCP server listening on: %v", addr)
			if e := s.ListenAndServe(); e != nil {
				panic(e)
			}
		}()
	}
	return server, nil
}

func (s *Server) Shutdown() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

func Cname(host string) string {
	host = strings.ToLower(host)
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	return host
}

func newStaticClientConfig(ips []string) (*dns.ClientConfig, error) {
	s := ``
	for _, ip := range ips {
		s += fmt.Sprintf("nameserver %s\n", ip)
	}
	r := strings.NewReader(s)
	return dns.ClientConfigFromReader(r)
}

func (h *Handler) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	var (
		reply   dns.Msg
		handled bool
	)
	reply.SetReply(req)
	logrus.Debugf("handleQuery received DNS query: %v", req)
	for _, q := range req.Question {
		hdr := dns.RR_Header{
			Name:   q.Name,
			Rrtype: q.Qtype,
			Class:  q.Qclass,
			Ttl:    5,
		}
		switch q.Qtype {
		case dns.TypeAAAA:
			if !h.ipv6 {
				handled = true
				break
			}
			fallthrough
		case dns.TypeA:
			var err error
			var addrs []net.IP
			if _, ok := h.hostToIP[q.Name]; ok {
				addrs = []net.IP{h.hostToIP[q.Name]}
			} else {
				addrs, err = net.LookupIP(q.Name)
				if err != nil {
					logrus.Errorf("handleQuery lookup IP failed: %v", err)
					continue
				}
			}
			if len(addrs) > 0 {
				for _, ip := range addrs {
					var a dns.RR
					ipv6 := ip.To4() == nil
					if q.Qtype == dns.TypeA && !ipv6 {
						hdr.Rrtype = dns.TypeA
						a = &dns.A{
							Hdr: hdr,
							A:   ip.To4(),
						}
					} else if q.Qtype == dns.TypeAAAA && ipv6 {
						hdr.Rrtype = dns.TypeAAAA
						a = &dns.AAAA{
							Hdr:  hdr,
							AAAA: ip.To16(),
						}
					} else {
						continue
					}
					reply.Answer = append(reply.Answer, a)
					handled = true
				}
			}
		case dns.TypeCNAME:
			cname := q.Name
			if _, ok := h.cnameToHost[cname]; ok {
				cname = h.cnameToHost[cname]
			}
			var err error
			if _, ok := h.hostToIP[cname]; !ok {
				cname, err = net.LookupCNAME(cname)
				if err != nil {
					logrus.Errorf("handleQuery lookup CNAME failed: %v", err)
					continue
				}
			}
			if cname != "" && cname != q.Name {
				hdr.Rrtype = dns.TypeCNAME
				a := &dns.CNAME{
					Hdr:    hdr,
					Target: cname,
				}
				reply.Answer = append(reply.Answer, a)
				handled = true
			}
		case dns.TypeTXT:
			txt, err := net.LookupTXT(q.Name)
			if err != nil {
				logrus.Errorf("handleQuery lookup TXT failed: %v", err)
				continue
			}
			if len(txt) > 0 {
				a := &dns.TXT{
					Hdr: hdr,
					Txt: txt,
				}
				reply.Answer = append(reply.Answer, a)
				handled = true
			}
		case dns.TypeNS:
			ns, err := net.LookupNS(q.Name)
			if err != nil {
				logrus.Errorf("handleQuery lookup NS failed: %v", err)
				continue
			}
			if len(ns) > 0 {
				for _, s := range ns {
					if s.Host != "" {
						a := &dns.NS{
							Hdr: hdr,
							Ns:  s.Host,
						}
						reply.Answer = append(reply.Answer, a)
						handled = true
					}
				}
			}
		case dns.TypeMX:
			mx, err := net.LookupMX(q.Name)
			if err != nil {
				logrus.Errorf("handleQuery lookup MX failed: %v", err)
				continue
			}
			if len(mx) > 0 {
				for _, s := range mx {
					if s.Host != "" {
						a := &dns.MX{
							Hdr:        hdr,
							Mx:         s.Host,
							Preference: s.Pref,
						}
						reply.Answer = append(reply.Answer, a)
						handled = true
					}
				}
			}
		case dns.TypeSRV:
			_, addrs, err := net.LookupSRV("", "", q.Name)
			if err != nil {
				logrus.Errorf("handleQuery lookup SRV failed: %v", err)
				continue
			}
			hdr.Rrtype = dns.TypeSRV
			for _, addr := range addrs {
				a := &dns.SRV{
					Hdr:      hdr,
					Target:   addr.Target,
					Port:     addr.Port,
					Priority: addr.Priority,
					Weight:   addr.Weight,
				}
				reply.Answer = append(reply.Answer, a)
				handled = true
			}
		}
	}
	if handled {
		if h.truncate {
			reply.Truncate(truncateSize)
		}
		if err := w.WriteMsg(&reply); err != nil {
			logrus.Errorf("handleQuery failed writing DNS reply: %v", err)
		}

		return
	}
	h.handleDefault(w, req)
}

func (h *Handler) handleDefault(w dns.ResponseWriter, req *dns.Msg) {
	logrus.Debugf("handleDefault for %v", req)
	for _, client := range h.clients {
		for _, srv := range h.clientConfig.Servers {
			addr := fmt.Sprintf("%s:%s", srv, h.clientConfig.Port)
			reply, _, err := client.Exchange(req, addr)
			if err != nil {
				logrus.Errorf("handleDefault failed to perform a synchronous query with upstream [%v]: %v", addr, err)
				continue
			}
			if h.truncate {
				logrus.Debugf("handleDefault truncating reply: %v", reply)
				reply.Truncate(truncateSize)
			}
			if err = w.WriteMsg(reply); err != nil {
				logrus.Errorf("handleDefault failed writing DNS reply to [%v]: %v", addr, err)
			}
			return
		}
	}
	var reply dns.Msg
	reply.SetReply(req)
	if h.truncate {
		logrus.Debugf("handleDefault truncating reply: %v", reply)
		reply.Truncate(truncateSize)
	}
	if err := w.WriteMsg(&reply); err != nil {
		logrus.Errorf("handleDefault failed writing DNS reply: %v", err)
	}
}
