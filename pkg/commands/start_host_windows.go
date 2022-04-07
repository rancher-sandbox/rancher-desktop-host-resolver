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
	log"github.com/sirupsen/logrus"
)

func StartVsockHost(IPv6 bool, hosts map[string]string, upstreamServers []string) error {
	l, err := vmsock.Listen()
	if err != nil {
		return err
	}
	options := dns.ServerOptions{
		IPv6:            IPv6,
		StaticHosts:     hosts,
		UpstreamServers: upstreamServers,
		Listener:        l,
	}
	srv, err := dns.StartWithListener(options)
	if err != nil {
		return err
	}
	log.Infof("Started vsock-host srv %+v", srv)
	defer srv.Shutdown()

	run()
	return nil
}
