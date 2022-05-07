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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var hostViper = viper.New()

// hostCmd represents the AF_VSOCK host process that run in a host machine.
// It receives all the DNS queries from vsock-peer over the AF_VSOCK connection for resolution.
// Upon startup it attempts to finds the peer process over AF_VSOCK connection by establishing
// a handshake and verifying a seed string to make sure it is communicating with the right VM.
var (
	hostCmd = &cobra.Command{
		Use:   "vsock-host",
		Short: "Host-resolver vsock-host process",
		Long: `Vsock-host runs the host-resolver as a host for AF_VSOCK in a host machine.
It handles and forwards both TCP and UDP DNS queries over a virtual socket for the peer
that runs inside a VM.

 --------------------HOST-------------------------------------WSL DISTRO-----------
| vsock-host | <----- AF_VSOCK -----> [ VM ] <----- AF_VSOCK -----> | vsock-peer   |
 ----------------------------------------------------------------------------------`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ipv6 := hostViper.GetBool("ipv6")
			upstreamServers := hostViper.GetStringSlice("upstream-servers")

			allSettings := hostViper.AllSettings()
			builtInHosts := allSettings["built-in-hosts"]
			hosts, err := cast.ToStringMapStringE(builtInHosts)
			if err != nil {
				logrus.Errorf("reading built-in-hosts value: %v", err)
			}

			return commands.StartVsockHost(ipv6, hosts, upstreamServers)
		},
	}
)

func init() {
	hostCmd.Flags().BoolP("ipv6", "6", false, "Enable IPv6 address family.")
	hostCmd.Flags().StringToStringP("built-in-hosts", "c", map[string]string{},
		"List of built-in CNAMEs to IPv4, IPv6 or IPv4-mapped IPv6 in host.rancherdesktop.io=111.111.111.111 format.")
	hostCmd.Flags().StringArrayP("upstream-servers", "s", []string{}, "List of IP addresses for upstream DNS servers.")
	hostViper.AutomaticEnv()
	if err := hostViper.BindPFlags(hostCmd.Flags()); err != nil {
		logrus.Fatalf("Faild to bind host flags: %v", err)
	}
	rootCmd.AddCommand(hostCmd)
}
