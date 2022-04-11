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
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/commands"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var (
	addr             string
	tcpPort, udpPort int
	ipv6             bool
	hosts            map[string]string
	upstreamServers  []string

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Runs the host-resolver with a given arguments",
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.Start(addr, udpPort, tcpPort, ipv6, hosts, upstreamServers)
		},
	}
)

func init() {
	runCmd.Flags().StringVarP(&addr, "listen-address", "a", "", "Address to listen on, \":dnsPort\" if empty.")
	runCmd.Flags().IntVarP(&tcpPort, "tcp-port", "t", 0, "TCP port to listen on, if non provided random port will be chosen.")
	runCmd.Flags().IntVarP(&udpPort, "udp-port", "u", 0, "UDP port to listen on, if non provided random port will be chosen.")
	runCmd.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "Enable IPv6 address family.")
	runCmd.Flags().StringToStringVarP(&hosts, "built-in-hosts", "c", map[string]string{}, "List of built-in Cnames to IPv4, IPv6 or IPv4-mapped IPv6 in host.rd.internal=111.111.111.111,com.backend.process=2001:db8::68 format.")
	runCmd.Flags().StringArrayVarP(&upstreamServers, "upstream-servers", "s", []string{}, "List of IP addresses for upstream DNS servers.")
	rootCmd.AddCommand(runCmd)
}
