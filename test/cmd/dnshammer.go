/*
Copyright © 2022 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/rancher-sandbox/rancher-desktop-host-resolver/test/testdns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const lookupTimeoutSec = 10 // 10s timeout should be adequate
const defaultRequestNumber = 0

// dnshammerCmd represents the dnshammer command
var dnshammerCmd = &cobra.Command{
	Use:   "dnshammer",
	Short: "dnshammer is a utility for hammering the DNS server",
	Long: `DNS Hammer is used for testing purporses against a DNS server, specifically
	Rancher Desktop Host Resovler stub DNS. It can handle specified number of records
	along with resource records types and interval (backoff)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("running dnshammer")
		addr, err := cmd.Flags().GetString("server-address")
		if err != nil {
			return err
		}
		n, err := cmd.Flags().GetInt("request-number")
		if err != nil {
			return err
		}
		records, err := cmd.Flags().GetStringToString("rr-type")
		if err != nil {
			return err
		}
		return dnsQuery(addr, n, records)
	},
}

func init() {
	dnshammerCmd.Flags().StringP("server-address", "a", "127.0.0.1:53", "Address of the DNS server.")
	dnshammerCmd.Flags().StringToStringP("rr-type", "r", map[string]string{},
		`List of desired resource records mapped to the csv test data file.
	Supported records are: A, CNAME, TXT, NS, MX, SRV. Accepted Format: A=Arecords.csv,CNAME=cnames.csv`)
	dnshammerCmd.Flags().IntP("request-number", "n", defaultRequestNumber,
		"Number of request against the DNS server, if not provided all the entries in a given test data will be used.")
	rootCmd.AddCommand(dnshammerCmd)
}

func dnsQuery(srvAddr string, n int, records map[string]string) error {
	for rr, path := range records {
		switch rr { //nolint:gocritic // this will have additional cases soon
		case "A":
			arecords := testdns.LoadRecords(path)
			if err := do(srvAddr, n, arecords); err != nil {
				return err
			}
		}
	}
	return nil
}

func do(addr string, n int, records map[string][]string) error {
	var i int
	for host, ips := range records {
		if n != defaultRequestNumber && i == n {
			break
		}
		ipResults, err := dnsLookup(addr, "udp", host)
		if err != nil {
			return err
		}
		if !compare(ips, ipToString(ipResults)) {
			return fmt.Errorf("expected IP addresses to match, got: %v wanted: %v", ipResults, ips)
		}
		i++
	}
	logrus.Infof("Successfully tested %v records, against: %v", i, addr)
	return nil
}

func ipToString(ips []net.IP) (out []string) {
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func compare(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i, ip := range a {
		if ip != b[i] {
			return false
		}
	}
	return true
}

func dnsLookup(addr, resolverProtocol, domain string) ([]net.IP, error) {
	resolver := net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, resolverProtocol, addr)
		},
	}
	logrus.Debugf("[DNS] lookup on %s [%s] -> %s", addr, resolverProtocol, domain)
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeoutSec*time.Second)
	defer cancel()
	return resolver.LookupIP(ctx, "ip4", domain)
}
