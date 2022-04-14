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
	"os"
	"os/signal"
	"syscall"

	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/dns"
	"github.com/sirupsen/logrus"
)

func Start(address string, udpLocalPort, tcpLocalPort int, ipv6 bool, hosts map[string]string, upstreamServers []string) error {
	srv, err := dns.Start(dns.ServerOptions{
		Address:         address,
		UDPPort:         udpLocalPort,
		TCPPort:         tcpLocalPort,
		IPv6:            ipv6,
		StaticHosts:     hosts,
		UpstreamServers: upstreamServers,
	},
	)
	if err != nil {
		return err
	}
	logrus.Infof("Started srv %+v", srv)
	defer srv.Shutdown()

	terminateCh := make(chan os.Signal, 1)
	signal.Notify(terminateCh, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)

	for range terminateCh {
		logrus.Info("host-resolver stopped.")
		break
	}
	return nil
}
