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

package vmsock

import (
	"fmt"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/linuxkit/virtsock/pkg/hvsock"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

func vmGuid() (hvsock.GUID, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\HostComputeService\VolatileStore\ComputeSystem`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return hvsock.GUIDZero, fmt.Errorf("could not retrieve registry key, is WSL VM running? %w", err)
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(0)
	if err != nil {
		return hvsock.GUIDZero, fmt.Errorf("machine IDs can not be read in registry: %w", err)
	}

	found := make(chan hvsock.GUID)
	done := make(chan bool)
	defer close(done)

	for _, name := range names {
		vmGuid, err := hvsock.GUIDFromString(name)
		if err != nil {
			log.Errorf("invalid VM name: [%s], err: %w\n", name, err)
			continue
		}

		go hostHandshake(vmGuid, found, done)
	}

	return <-found, nil
}

func hostHandshake(vmGuid hvsock.GUID, found chan hvsock.GUID, quit chan bool) {
	svcPort, err := hvsock.GUIDFromString(winio.VsockServiceID(PeerHandshakePort).String())
	if err != nil {
		log.Fatalf("hostHandshake parsing svc port: %v", err)
	}
	addr := hvsock.Addr{
		VMID:      vmGuid,
		ServiceID: svcPort,
	}

	attempInterval := time.NewTicker(time.Second * 1)
	// maybe this needs to be longer in a real deployment
	bailOut := time.After(time.Second * 10)
	attempt := 1
	for {
		select {
		case <-quit:
			log.Debugf("attempt to handshake with [%s], goroutine is terminated", vmGuid.String())
			return
		case <-attempInterval.C:
			conn, err := hvsock.Dial(addr)
			if err != nil {
				log.Errorf("attempt[%d] to handshake failed: %v", attempt, err)
				attempt++
				continue
			}
			defer conn.Close()
			seed := make([]byte, len(SeedPhrase))
			_, err = conn.Read(seed)
			if err != nil {
				log.Errorf("hosthandshake attempt to read the seed: %v", err)
				return
			}
			if string(seed) == SeedPhrase {
				log.Infof("successfully estabilished a handshake with a peer: %s", vmGuid.String())
				found <- vmGuid
			}
		case <-bailOut:
			log.Fatalf("all attempt to find a peer on WSL VM [%s] failed, is WSL or Peer running?", vmGuid.String())
		}
	}
}
