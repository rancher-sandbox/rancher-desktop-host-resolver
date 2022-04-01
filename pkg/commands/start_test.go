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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	tcpPort = "54"
	udpPort = "53"
)

func TestStart(t *testing.T) {
	cmd := run(t, "127.0.0.1", tcpPort, udpPort, "host.rd.test=111.111.111.111,host2.rd.test=222.222.222.222")
	defer cmd.Process.Kill()

	t.Logf("Checking for TCP port is running on %v", tcpPort)
	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%s", tcpPort))
	if tcpListener != nil {
		defer tcpListener.Close()
	}
	require.Errorf(t, err, "host-resolver is not listening on TCP port %s", tcpPort)

	t.Logf("Checking for UDP port is running on %v", udpPort)
	udpListener, err := net.Listen("udp", fmt.Sprintf(":%s", udpPort))
	if udpListener != nil {
		defer udpListener.Close()
	}
	require.Errorf(t, err, "host-resolver is not listening on UDP port %s", udpPort)

	output := netstat(t)

	exist := strings.Contains(string(output), fmt.Sprintf("%v/host-resolver", cmd.Process.Pid))
	require.Exactly(t, exist, true, "Expected the same Pid")
}

func TestQueryTCP(t *testing.T) {
	t.Log("Checking for TCP port on 54")
	cmd := run(t, "127.0.0.1", tcpPort, udpPort, "host.rd.test=111.111.111.111,host2.rd.test=222.222.222.222")
	defer cmd.Process.Kill()

	addrs, err := dnsLookup(t, tcpPort, "tcp", "host.rd.test")
	require.NoError(t, err, "Lookup IP failed")
	require.Exactly(t, len(addrs), 1, "Expect only one address")
	require.Exactly(t, addrs[0].String(), "111.111.111.111")
}

func TestQueryUDP(t *testing.T) {
	t.Log("Checking for UDP port on 53")
	cmd := run(t, "127.0.0.1", tcpPort, udpPort, "host.rd.test=111.111.111.111,host2.rd.test=222.222.222.222")
	defer cmd.Process.Kill()

	addrs, err := dnsLookup(t, udpPort, "udp", "host2.rd.test")
	require.NoError(t, err, "Lookup IP failed")
	require.Exactly(t, len(addrs), 1, "Expect only one address")
	require.Exactly(t, addrs[0].String(), "222.222.222.222")
}

func run(t *testing.T, ip, tcpPort, udpPort, hosts string) *exec.Cmd {
	cmd := exec.Command("/host-resolver", "run", "-a", ip, "-t", tcpPort, "-u", udpPort, "-c", hosts, "&")
	err := cmd.Start()
	require.NoError(t, err, "host-resolver run failed")
	// little bit of pause is needed for the process to start
	// since cmd.Run() doesn't work in this situation :{
	time.Sleep(time.Second * 1)
	return cmd
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

func netstat(t *testing.T) []byte {
	out, err := exec.Command("netstat", "-nlp").Output()
	require.NoError(t, err, "netstat -nlp")
	t.Logf("%s\n", out)
	return out
}
