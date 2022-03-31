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
package commands

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStart(t *testing.T) {
	netstat(t)

	t.Log("Checking for TCP port on 54")
	tcpPort := "54"
	_, err := net.Listen("tcp", fmt.Sprintf(":%s", tcpPort))
	require.Errorf(t, err, "host-resolver is not listening on TCP port %s", tcpPort)

	t.Log("Checking for UDP port on 53")
	udpPort := "53"
	_, err = net.Listen("udp", fmt.Sprintf(":%s", udpPort))
	require.Errorf(t, err, "host-resolver is not listening on UDP port %s", udpPort)
}

func TestQueryTCP(t *testing.T) {
	t.Log("Checking for TCP port on 54")
	addrs, err := dnsLookup(t, "54", "tcp", "host.rd.internal")
	require.NoError(t, err, "Lookup IP failed")
	require.Exactly(t, len(addrs), 1, "Expect only one address")
	require.Exactly(t, addrs[0].String(), "111.111.111.111")
}

func TestQueryUDP(t *testing.T) {
	t.Log("Checking for UDP port on 53")
	addrs, err := dnsLookup(t, "53", "udp", "host2.rd.internal")
	require.NoError(t, err, "Lookup IP failed")
	require.Exactly(t, len(addrs), 1, "Expect only one address")
	require.Exactly(t, addrs[0].String(), "222.222.222.222")
}

func dnsLookup(t *testing.T, resolverPort, resolverProtocol, domain string) ([]net.IP, error) {
	resolver := net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, resolverProtocol, fmt.Sprintf(":%s", resolverPort))
		},
	}
	t.Logf("[DNS] lookup on :%s and %s -> %s", resolverPort, resolverProtocol, domain)
	// 10s timeout should be adequate
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return resolver.LookupIP(ctx, "ip4", domain)

}

func netstat(t *testing.T) {
	out, err := exec.Command("netstat", "-nlp").Output()
	require.NoError(t, err, "netstat -nlp")
	t.Logf("%s\n", out)
}
