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
	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"

	rddns "github.com/lima-vm/lima/pkg/hostagent/dns"
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/vmsock"
)

// StartVsockHost attempts to start two AF_VSOCK listeners, one acting
// for TCP (stream) and the other for UDP (datagram); it then waits for the
// exit signal, if all fails it returns an appropriate error
func StartVsockHost(ipv6 bool, hosts map[string]string, upstreamServers []string) error {
	vmGUID, err := vmsock.GetVMGUID()
	if err != nil {
		return err
	}

	tcpOpts := rddns.HandlerOptions{
		IPv6:            ipv6,
		StaticHosts:     hosts,
		UpstreamServers: upstreamServers,
		TruncateReply:   false,
	}
	tcpServer, err := startDNSServer(vmGUID, vmsock.HostTCPListenPort, tcpOpts)
	if err != nil {
		logrus.Panicf("StartVsockHost failed to start TCP DNS server: %v", err)
	}

	logrus.Infof("Started vsock-host AF_VSOCK stream server on VM: %v listening on port: %v", vmGUID.String(), vmsock.HostTCPListenPort)
	defer func() {
		if err := tcpServer.Shutdown(); err != nil {
			logrus.Errorf("Shutting down TCP server failed: %v", err)
		}
	}()

	udpOpts := rddns.HandlerOptions{
		IPv6:            ipv6,
		StaticHosts:     hosts,
		UpstreamServers: upstreamServers,
		TruncateReply:   true,
	}
	udpServer, err := startDNSServer(vmGUID, vmsock.HostUDPListenPort, udpOpts)
	if err != nil {
		logrus.Panicf("StartVsockHost failed to start UDP DNS server: %v", err)
	}
	logrus.Infof("Started vsock-host AF_VSOCK datagram server on VM: %v listening on port: %v", vmGUID.String(), vmsock.HostUDPListenPort)
	defer func() {
		if err := udpServer.Shutdown(); err != nil {
			logrus.Errorf("Shutting down UDP server failed: %v", err)
		}
	}()

	waitForExitSignal()
	return nil
}

func startDNSServer(vmGUID hvsock.GUID, vsockPort uint32, opts rddns.HandlerOptions) (*dns.Server, error) {
	listner, err := vmsock.Listen(vmGUID, vsockPort)
	if err != nil {
		return nil, err
	}
	handler, err := rddns.NewHandler(opts)
	if err != nil {
		return nil, err
	}
	server := &dns.Server{Net: "tcp", Listener: listner, Handler: handler}
	go func() {
		if e := server.ActivateAndServe(); e != nil {
			panic(e)
		}
	}()
	return server, nil
}
