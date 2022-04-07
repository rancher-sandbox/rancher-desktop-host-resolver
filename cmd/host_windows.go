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

// hostCmd represents the host command
var (
	hostCmd = &cobra.Command{
		Use:   "vsock-host",
		Short: "Host-resolver vsock-host process",
		Long: `Vsock-host runs the host-resolver as a host for AF_VSOCK in a host machine.
It handles and forwards both TCP and UDP DNS queries over a virtual socket for the peer
that runs inside a VM.

--------------------HOST-------------------------------------WSL DISTRO------------
| vsock-host | <----- AF_VOSOCK -----> [ VM ] <----- AF_VOSOCK -----> | vsock-peer |
-----------------------------------------------------------------------------------`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ipv6, err := cmd.Flags().GetBool("ipv6")
			if err != nil {
				return err
			}
			hosts, err := cmd.Flags().GetStringToString("built-in-hosts")
			if err != nil {
				return err
			}
			upstreamServers, err := cmd.Flags().GetStringArray("upstream-servers")
			if err != nil {
				return err
			}
			return commands.StartVsockHost(ipv6, hosts, upstreamServers)
		},
	}
)

func init() {
	hostCmd.Flags().BoolP("ipv6", "6", false, "Enable IPv6 address family.")
	hostCmd.Flags().StringToStringP("built-in-hosts", "c", map[string]string{}, "List of built-in Cnames to IPv4, IPv6 or IPv4-mapped IPv6 in host.rd.internal=111.111.111.111,com.backend.process=2001:db8::68 format.")
	hostCmd.Flags().StringArrayP("upstream-servers", "s", []string{}, "List of IP addresses for upstream DNS servers.")
	rootCmd.AddCommand(hostCmd)
}
