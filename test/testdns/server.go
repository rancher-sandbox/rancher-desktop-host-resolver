package testdns

import (
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const truncateSize = 512

type Handler struct {
	Truncate     bool
	Arecords     map[string][]string
	TXTrecords   map[string][]string
	CNAMErecords map[string][]string
}

type Server struct {
	Addr                   string
	TCPPort                string
	UDPPort                string
	TCPHandler, UDPHandler *Handler
}

func (s *Server) Run() {
	g := new(errgroup.Group)
	udpSrv := &dns.Server{Addr: net.JoinHostPort(s.Addr, s.UDPPort), Net: "udp", Handler: s.UDPHandler}
	defer func() {
		if err := udpSrv.Shutdown(); err != nil {
			logrus.Errorf("shutting down UDP server: %v", err)
		}
	}()
	g.Go(udpSrv.ListenAndServe)

	tcpSrv := &dns.Server{Addr: net.JoinHostPort(s.Addr, s.TCPPort), Net: "tcp", Handler: s.TCPHandler}
	defer func() {
		if err := tcpSrv.Shutdown(); err != nil {
			logrus.Errorf("shutting down TCP server: %v", err)
		}
	}()
	g.Go(tcpSrv.ListenAndServe)

	if err := g.Wait(); err != nil {
		logrus.Fatalf("ListenAndServe error: %v", err)
	}
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	// we might handle other OpCodes later
	if r.Opcode != dns.OpcodeQuery {
		return
	}
	h.parseReply(msg)
	if h.Truncate {
		msg.Truncate(truncateSize)
	}
	if err := w.WriteMsg(msg); err != nil {
		logrus.Errorf("ServeDNS trying to write message in udpHandler: %v", err)
	}
}

func (h *Handler) parseReply(msg *dns.Msg) {
	logrus.Debugf("ServeDNS handling request: %v", msg.Question)
	msg.Authoritative = true
	for _, q := range msg.Question {
		domain := q.Name
		switch q.Qtype {
		case dns.TypeA:
			if addresses, ok := h.Arecords[domain]; ok {
				for _, addr := range addresses {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   domain,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    180,
						},
						A: net.ParseIP(addr),
					})
				}
			}
		case dns.TypeTXT:
			if txtRecords, ok := h.TXTrecords[domain]; ok {
				for _, txt := range txtRecords {
					msg.Answer = append(msg.Answer, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   domain,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    180,
						},
						Txt: []string{txt},
					})
				}
			}
		case dns.TypeCNAME:
			if host, ok := h.CNAMErecords[domain]; ok {
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   domain,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    180,
					},
					Target: host[0], // there should only be one host
				})
			}
		}
	}
}
