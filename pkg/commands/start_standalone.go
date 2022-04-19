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
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/dns"
	log "github.com/sirupsen/logrus"
)

func StartStandAloneServer(options *dns.ServerOptions) error {
	var err error
	if options.UDPPort == 0 {
		options.UDPPort, err = randomUDPPort()
		if err != nil {
			return err
		}
	}
	if options.TCPPort == 0 {
		options.TCPPort, err = randomTCPPort()
		if err != nil {
			return err
		}
	}
	srv, err := dns.Start(options)
	if err != nil {
		return err
	}
	log.Infof("Started Stand Alone srv %+v", srv)
	defer srv.Shutdown()

	run()
	return nil
}

func randomTCPPort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randomUDPPort() (int, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port, nil
}

func run() {
	terminateCh := make(chan os.Signal, 1)
	signal.Notify(terminateCh, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)

	for range terminateCh {
		log.Info("host-resolver stopped.")
		break
	}
}
