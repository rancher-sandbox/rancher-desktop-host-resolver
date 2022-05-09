package test

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var domainToIP = loadRecords("testdata/test-300.csv")

const truncateSize = 512

type handler struct {
	truncate bool
}

type Server struct {
	Addr    string
	TCPPort string
	UDPPort string
}

func (s *Server) Run() {
	g := new(errgroup.Group)
	udpSrv := &dns.Server{Addr: net.JoinHostPort(s.Addr, s.UDPPort), Net: "udp", Handler: &handler{truncate: true}}
	defer func() {
		if err := udpSrv.Shutdown(); err != nil {
			logrus.Errorf("shutting down UDP server: %v", err)
		}
	}()
	g.Go(udpSrv.ListenAndServe)

	tcpSrv := &dns.Server{Addr: net.JoinHostPort(s.Addr, s.TCPPort), Net: "tcp", Handler: &handler{}}
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

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = false
	// we might handle other OpCodes later
	if r.Opcode != dns.OpcodeQuery {
		return
	}
	parseReply(msg)
	if h.truncate {
		msg.Truncate(truncateSize)
	}
	err := w.WriteMsg(msg)
	if err != nil {
		logrus.Errorf("ServeDNS trying to write message in udpHandler: %v", err)
	}
}

func parseReply(msg *dns.Msg) {
	logrus.Infof("ServeDNS handling request: %v", msg.Question)
	for _, q := range msg.Question {
		switch q.Qtype { //nolint:gocritic // this will have additional cases soon
		case dns.TypeA:
			msg.Authoritative = true
			domain := q.Name
			addresses, ok := domainToIP[domain]
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

func loadRecords(path string) map[string][]string {
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
