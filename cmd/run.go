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
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var runViper = viper.New()

// runCmd represent the standalone command, it startup a standalone server that listens on a given
// IP and ports along with other specified arguments. The purpose of this process is mainly
// for testing of the contract with underlying DNS provider, debugging and benchmarking.
var (
	runCmd = &cobra.Command{
		Use:   "standalone",
		Short: "Runs the host-resolver standalone server with a given arguments",
		Long: `Runs the host-resolver in standalone mode; this mode allows the host-resolver to
attach to a defined IP and ports with given options. This mode is ideal for testing the contract
with the underlying DNS server. Use this mode for testing, debugging and benchmarks.
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.StartStandAloneServer(&dns.ServerOptions{
				Address: runViper.GetString("listen-address"),
				UDPPort: runViper.GetInt("udp-port"),
				TCPPort: runViper.GetInt("tcp-port"),
				HandlerOptions: dns.HandlerOptions{
					IPv6:            runViper.GetBool("ipv6"),
					StaticHosts:     runViper.GetStringMapString("built-in-hosts"),
					UpstreamServers: runViper.GetStringSlice("upstream-servers"),
				},
			})
		},
	}
)

func init() {
	runCmd.Flags().StringP("listen-address", "a", "", "Address to listen on, \":dnsPort\" if empty.")
	runCmd.Flags().IntP("tcp-port", "t", 0, "TCP port to listen on, if non provided random port will be chosen.")
	runCmd.Flags().IntP("udp-port", "u", 0, "UDP port to listen on, if non provided random port will be chosen.")
	runCmd.Flags().BoolP("ipv6", "6", false, "Enable IPv6 address family.")
	runCmd.Flags().StringToStringP(
		"built-in-hosts",
		"c",
		map[string]string{},
		"List of built-in Cnames to IPv4, IPv6 or IPv4-mapped IPv6 in host.rd.internal=111.111.111.111,com.backend.process=2001:db8::68 format.")
	runCmd.Flags().StringArrayP("upstream-servers", "s", []string{}, "List of IP addresses for upstream DNS servers.")
	runViper.AutomaticEnv()
	if err := runViper.BindPFlags(runCmd.Flags()); err != nil {
		logrus.Fatalf("Faild to bind standalone server flags: %v", err)
	}
	rootCmd.AddCommand(runCmd)
}
