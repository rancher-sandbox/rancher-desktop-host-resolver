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
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/dns"
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/vmsock"
	log "github.com/sirupsen/logrus"
)

// StartVsockHost attempts to start two AF_VSOCK listeners, one acting
// for TCP (stream) and the other for UDP (datagram); it then waits for the
// exit signal, if all fails it returns an appropriate error
func StartVsockHost(ipv6 bool, hosts map[string]string, upstreamServers []string) error {
	vmGUID, err := vmsock.GetVMGUID()
	if err != nil {
		return err
	}
	streamListener, err := vmsock.Listen(vmGUID, vmsock.HostTCPListenPort)
	if err != nil {
		return err
	}
	streamSrv, err := dns.StartWithListener(
		&dns.ServerOptions{
			IPv6:            ipv6,
			StaticHosts:     hosts,
			UpstreamServers: upstreamServers,
			Listener:        streamListener,
			TruncateReply:   false,
		})
	if err != nil {
		return err
	}
	log.Infof("Started vsock-host AF_VSOCK stream server on VM: %v listening on port: %v", vmGUID.String(), vmsock.HostTCPListenPort)
	defer streamSrv.Shutdown()

	dgramListener, err := vmsock.Listen(vmGUID, vmsock.HostUDPListenPort)
	if err != nil {
		return err
	}
	dgramSrv, err := dns.StartWithListener(
		&dns.ServerOptions{
			IPv6:            ipv6,
			StaticHosts:     hosts,
			UpstreamServers: upstreamServers,
			Listener:        dgramListener,
			TruncateReply:   true,
		})
	if err != nil {
		return err
	}
	log.Infof("Started vsock-host AF_VSOCK datagram server on VM: %v listening on port: %v", vmGUID.String(), vmsock.HostUDPListenPort)
	defer dgramSrv.Shutdown()

	waitForExitSignal()
	return nil
}
