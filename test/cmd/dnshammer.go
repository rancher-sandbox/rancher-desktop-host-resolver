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
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const lookupTimeout = time.Second * 10
const defaultRequestNumber = 0

// dnshammerCmd represents the dnshammer command
var dnshammerCmd = &cobra.Command{
	Use:   "dnshammer",
	Short: "dnshammer is a utility for hammering the DNS server",
	Long: `DNS Hammer is used for testing purporses against a DNS server, specifically
	Rancher Desktop Host Resovler stub DNS. It can handle specified number of records
	along with resource records types and interval (backoff)`,
	RunE: func(cmd *cobra.Command, args []string) error {
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
	Supported records are: A, TXT. Accepted Format: A=Arecords.csv,TXT=txtfile.csv`)
	dnshammerCmd.Flags().IntP("request-number", "n", defaultRequestNumber,
		"Number of request against the DNS server, if not provided all the entries in a given test data will be used.")
	rootCmd.AddCommand(dnshammerCmd)
}

func dnsQuery(srvAddr string, n int, records map[string]string) error {
	for rr, path := range records {
		switch rr {
		case "A":
			aRecords := loadRecords(path)
			if err := doA(srvAddr, n, aRecords); err != nil {
				return err
			}
		case "TXT":
			txtRecords := loadRecords(path)
			if err := doTXT(srvAddr, n, txtRecords); err != nil {
				return err
			}
		}
	}
	return nil
}

func doA(addr string, n int, records map[string][]string) error {
	var i int
	for host, ips := range records {
		if n != defaultRequestNumber && i == n {
			break
		}
		ipResults, err := lookupARecord(addr, "udp", host)
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

func doTXT(addr string, n int, records map[string][]string) error {
	var i int
	for host, txt := range records {
		if n != defaultRequestNumber && i == n {
			break
		}
		txtResults, err := lookupTXT(host)
		if err != nil {
			return err
		}
		if !contains(txt, txtResults) {
			return fmt.Errorf("expected TXT record to match, got: %v wanted: %v", txtResults, txt)
		}
		i++
	}
	logrus.Infof("Successfully tested %v records, against: %v", i, addr)
	return nil
}

func contains(expected, actual []string) bool {
	for _, t1 := range expected {
		for _, t2 := range actual {
			if !strings.Contains(t2, t1) {
				return false
			}
		}
	}
	return true
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

func ipToString(ips []net.IP) (out []string) {
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func lookupARecord(addr, resolverProtocol, domain string) ([]net.IP, error) {
	resolver := net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, resolverProtocol, addr)
		},
	}
	logrus.Debugf("[DNS] lookup on %s [%s] -> %s", addr, resolverProtocol, domain)
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return resolver.LookupIP(ctx, "ip4", domain)
}

func lookupTXT(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return net.DefaultResolver.LookupTXT(ctx, domain)
}

func loadRecords(p string) map[string][]string {
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
	csvReader.FieldsPerRecord = -1 // disable expected fields per record
	fileData, err := csvReader.ReadAll()
	if err != nil {
		logrus.Panicf("reading csv file: %v err: %v", path, err)
	}

	var domain string
	records := make(map[string][]string)
	for _, line := range fileData {
		var data = []string{}
		for j, field := range line {
			if j == 0 {
				domain = field
			} else {
				data = append(data, field)
			}
			records[domain] = data
		}
	}
	return records
}
