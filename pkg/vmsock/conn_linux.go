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
	"encoding/binary"
	"fmt"
	"net"

	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/rancher-sandbox/rancher-desktop/src/go/wsl-helper/pkg/dockerproxy/util"
	log "github.com/sirupsen/logrus"
)

const UDPMaxBufer = 1024

func ListenTCP(addr string, port int) error {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(addr), Port: port})
	if err != nil {
		return fmt.Errorf("ListenTCP: %w", err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Errorf("ListenTCP accept connection: %v", err)
			continue
		}
		go handleTCP(conn)
	}
}

func handleTCP(tConn net.Conn) {
	vConn, err := vsock.Dial(vsock.CIDHost, HostListenPort)
	if err != nil {
		log.Fatalf("handleTCP dial to vsock host: %v", err)
	}
	defer vConn.Close()

	err = util.Pipe(tConn, vConn)
	if err != nil {
		log.Errorf("handleTCP, stream error: %v", err)
		return
	}
}

func ListenUDP(addr string, port int) error {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(addr), Port: port})
	if err != nil {
		return fmt.Errorf("ListenUDP: %w", err)
	}
	defer l.Close()
	for {
		buf := make([]byte, UDPMaxBufer)
		n, addr, err := l.ReadFromUDP(buf)
		if err != nil {
			log.Errorf("ListenUDP, read error: %v", err)
			continue
		}
		log.Debugf("ListenUDP: received a connection from: %v with: %+v", addr, string(buf))
		go handleUDP(l, addr, appendHeaderLen(buf, n))
	}
}

func handleUDP(uConn *net.UDPConn, addr *net.UDPAddr, b []byte) {
	conn, err := vsock.Dial(vsock.CIDHost, HostListenPort)
	if err != nil {
		log.Fatalf("handleUDPConn dial to vsock host: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(b)
	if err != nil {
		log.Errorf("handleUDP write to vsock host: %v", err)
		return
	}
	data := make([]byte, UDPMaxBufer)
	_, err = conn.Read(data)
	if err != nil {
		log.Errorf("handleUDP read from vsock host: %v", err)
		return
	}
	// remove the tcp length from the beginning since that is the place for msg id ;b
	_, err = uConn.WriteToUDP(data[2:], addr)
	if err != nil {
		log.Errorf("handleUDP write to original requester: %v", err)
	}
}

// appendHeaderLen is to accommodate for the header length that exists in TCP buffer for DNS payload
// DNS server does a binary read on the first 8 byte(uint16) of the buffer for this length
// the UDP buffer does not include this header length, therefore it would need to be added
func appendHeaderLen(m []byte, n int) []byte {
	msg := make([]byte, 2+n)
	// we cannot do a binary.Write on net.Conn since this is a UDP Conn
	binary.BigEndian.PutUint16(msg, uint16(n))
	copy(msg[2:], m)
	return msg
}
