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
package helper

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// GetDnsInterfaces returns network interfaces that have active DNS servers associated to them.
// The filtering criteria requests all address families using AF_UNSPEC since interfaces can have
// DNS server addrs for IPv6 and not IPv4, or vice versa. It further checks the operation status of the
// adapter's address to make sure it is up. The final filter is to remove all the addresses without a
// DCHP server, this filter eliminates interfaces that are not dynamically configured
// e.g. VirtualBox Host-Only Network, vEthernet (WSL)
func GetDNSInterfaces() ([]*winipcfg.IPAdapterAddresses, error) {
	addrs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAll)
	if err != nil {
		return nil, err
	}
	var activeIfs []*winipcfg.IPAdapterAddresses
	for _, addr := range addrs {
		dnsAddrs, err := addr.LUID.DNS()
		if err != nil {
			return nil, err
		}
		if addr.OperStatus == winipcfg.IfOperStatusUp && len(dnsAddrs) != 0 && addr.DHCPv4Server.Sockaddr != nil {
			activeIfs = append(activeIfs, addr)
		}
	}
	return activeIfs, nil
}
