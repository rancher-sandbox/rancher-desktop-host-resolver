package testdns

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const truncateSize = 512

type Handler struct {
	truncate bool
	Arecords map[string][]string
}

func NewHandler(trucate bool) *Handler {
	return &Handler{
		truncate: trucate,
	}
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
	msg.Compress = false
	// we might handle other OpCodes later
	if r.Opcode != dns.OpcodeQuery {
		return
	}
	h.parseReply(msg)
	if h.truncate {
		msg.Truncate(truncateSize)
	}
	if err := w.WriteMsg(msg); err != nil {
		logrus.Errorf("ServeDNS trying to write message in udpHandler: %v", err)
	}
}

func (h *Handler) parseReply(msg *dns.Msg) {
	logrus.Debugf("ServeDNS handling request: %v", msg.Question)
	for _, q := range msg.Question {
		switch q.Qtype { //nolint:gocritic // this will have additional cases soon
		case dns.TypeA:
			msg.Authoritative = true
			domain := q.Name
			addresses, ok := h.Arecords[domain]
			if ok {
				for _, addr := range addresses {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   domain,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						A: net.ParseIP(addr),
					})
				}
			}
		}
	}
}

func LoadRecords(p string) map[string][]string {
	path := filepath.ToSlash(p)
	f, err := os.Open(path)
	if err != nil {
		logrus.Panicf("opening file: %v err: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			logrus.Errorf("loadRecords closing file: %v", err)
		}
	}()

	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		logrus.Panicf("reading csv file: %v err: %v", path, err)
	}

	var domain string
	records := make(map[string][]string)
	for _, line := range data {
		var ips = []string{}
		for j, field := range line {
			if j == 0 {
				domain = fmt.Sprintf("%s.", field)
			} else {
				ips = append(ips, field)
			}
			records[domain] = ips
		}
	}
	return records
}
