//go:build windows
// +build windows

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

package e2e

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/helper" //nolint:ignore
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/test/testdns"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	// for now we use this maybe this can be an env var from test
	wslDistroName  = "host-resolver-e2e-test"
	wslTarballName = "distro-0.21.tar"
	wslTarballURL  = "https://github.com/rancher-sandbox/rancher-desktop-wsl-distro/releases/download/v0.21/distro-0.21.tar"
	testSrvAddr    = "127.0.0.1"
	dnsPort        = "53"
)

func TestLookupARecords(t *testing.T) { //nolint:funlen
	tmpDir := t.TempDir()

	t.Logf("Dowloading %v wsl distro tarball", wslTarballName)
	tarballPath := filepath.Join(tmpDir, wslTarballName)

	err := downloadWSLTarball(tarballPath, wslTarballURL)
	require.NoErrorf(t, err, "Failed to download wsl distro tarball %v", wslTarballName)

	t.Logf("Creating %v wsl distro", wslDistroName)
	installCmd := cmdExec(
		tmpDir,
		"wsl",
		"--import",
		wslDistroName,
		".",
		tarballPath)
	err = installCmd.Run()
	require.NoErrorf(t, err, "Failed to install distro %v", wslDistroName)

	defer func() {
		t.Logf("Deleting %v wsl distro", wslDistroName)
		_, err = cmdRunWithOutput("wsl", "--unregister", wslDistroName)
		require.NoErrorf(t, err, "Failed to start distro %v", wslDistroName)
	}()

	// It takes a long time to start a new distro,
	// 20 sec is a long time but that's actually how long
	// it takes to start a distro without any flakeyness
	timeout := time.Second * 20
	tryInterval := time.Second * 2
	err = confirm(func() bool {
		// this is a way to figure out if the distro is running
		// there is an issue with wsl --list --running output
		// the buffer is not very useful for string search since it
		// returns some sort of unicode.
		out, err := cmdRunWithOutput("wsl", "--distribution", wslDistroName, "--exec", "/bin/wslpath", ".")
		if err != nil {
			return false
		}
		// remove all the weirdness from WSL output
		return strings.TrimSpace(out) == "."
	}, tryInterval, timeout)
	require.NoErrorf(t, err, "Failed to check if %v wsl distro is running", wslDistroName)

	dnsInfs, err := helper.GetDNSInterfaces()
	require.NoError(t, err, "Failed getting DNS addrs associated to interfaces")

	// This is to cache all the exsisting DNS addresses
	guidToDNSAddr, err := cacheExsitingDNSAddrs(dnsInfs)
	require.NoError(t, err, "Failed caching exsisting DNS server addresses")

	// restore the system DNS servers to the original state
	defer restoreSystemDNS(t, dnsInfs, guidToDNSAddr)

	t.Log("Updating network interfaces with test DNS server addr")
	// Update the dns addrs to test server
	updateSystemDNS(t, dnsInfs)

	t.Log("Building host-resolver host binary")
	err = buildBinaries("../../...", "windows", tmpDir)
	require.NoError(t, err, "Failed building host-resolver.exe")

	t.Log("Building host-resolver peer binary")
	err = buildBinaries("../../...", "linux", tmpDir)
	require.NoError(t, err, "Failed building host-resolver")

	aRecords := testdns.LoadRecords("../testdata/test-300.csv")

	tcpHandler := testdns.NewHandler(false)
	tcpHandler.Arecords = aRecords

	udpHandler := testdns.NewHandler(true)
	udpHandler.Arecords = aRecords

	testServer := testdns.Server{
		Addr:       testSrvAddr,
		TCPPort:    dnsPort,
		UDPPort:    dnsPort,
		TCPHandler: tcpHandler,
		UDPHandler: udpHandler,
	}
	t.Log("Starting test upstream DNS server")
	go testServer.Run()

	t.Logf("Starting host-resolver peer process in wsl [%v]", wslDistroName)
	peerCmd := cmdExec(
		tmpDir,
		"wsl", "--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./rancher-desktop-host-resolver", "vsock-peer")
	err = peerCmd.Start()
	require.NoError(t, err, "Starting host-resolver peer process faild")
	defer func() {
		_ = peerCmd.Process.Kill()
	}()

	t.Log("Starting host-resolver host process")
	resolverExecPath := fmt.Sprintf("%v/rancher-desktop-host-resolver.exe", tmpDir)
	hostCmd := cmdExec(
		tmpDir,
		resolverExecPath, "vsock-host",
		"--upstream-servers", fmt.Sprintf("[%v]", testSrvAddr))
	err = hostCmd.Start()
	require.NoError(t, err, "Starting host-resolver host process faild")
	defer func() {
		_ = hostCmd.Process.Kill()
	}()

	t.Log("Building DNS hammer binary")
	err = buildBinaries("../...", "linux", tmpDir)
	require.NoError(t, err, "Failed building dnsHammer")

	err = copyTestData("../testdata/test-300.csv", fmt.Sprintf("%s/test-300.csv", tmpDir))
	require.NoError(t, err, "Failed copying test data file")

	t.Log("Confirming host-resolver peer process is up")
	peerCmdTimeout := time.Second * 10
	confirm(func() bool { //nolint:errcheck // we don't care about the error
		p, _ := os.FindProcess(peerCmd.Process.Pid)
		return p.Pid == peerCmd.Process.Pid
	}, tryInterval, peerCmdTimeout)

	t.Logf("Running dns hammer test process in wsl [%v]", wslDistroName)
	dnsSrvAddr := net.JoinHostPort(testSrvAddr, dnsPort)
	runTestCmd := cmdExec(
		tmpDir,
		"wsl",
		"--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./test", "dnshammer",
		"--server-address", dnsSrvAddr,
		"--rr-type", "A=test-300.csv")
	err = runTestCmd.Run()
	require.NoError(t, err, "Running dns hammer against the peer process faild")
	_ = runTestCmd.Process.Kill()
}

// TODO (Nino-K): maybe this can be replaced by CI
func buildBinaries(path, goos, tmpDir string) error {
	buildCmd := exec.Command("go", "build", "-o", tmpDir, path)
	buildCmd.Env = os.Environ()
	buildCmd.Env = append(buildCmd.Env, fmt.Sprintf("GOOS=%s", goos))
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	return buildCmd.Run()
}

func cmdRunWithOutput(command string, args ...string) (string, error) {
	var outBuf, errBuf strings.Builder
	cmd := exec.Command(command, args...)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		return errBuf.String(), err
	}
	return outBuf.String(), nil
}

func cmdExec(execDir, command string, args ...string) *exec.Cmd {
	cmd := exec.Command(command, args...)
	if execDir != "" {
		cmd.Dir = execDir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func copyTestData(src, dst string) error {
	bytesRead, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, bytesRead, 0600)
}

func cacheExsitingDNSAddrs(adapterAddrs []*winipcfg.IPAdapterAddresses) (map[string][]netip.Addr, error) {
	guidToDNSAddrs := make(map[string][]netip.Addr)
	for _, a := range adapterAddrs {
		guid, err := a.LUID.GUID()
		if err != nil {
			return nil, err
		}
		dnsAddrs, err := a.LUID.DNS()
		if err != nil {
			return nil, err
		}
		guidToDNSAddrs[guid.String()] = dnsAddrs
	}
	return guidToDNSAddrs, nil
}

func confirm(command func() bool, interval, timeout time.Duration) error {
	tick := time.NewTicker(interval)
	terminate := time.After(timeout)

	for {
		select {
		case <-tick.C:
			if command() {
				return nil
			}
		case <-terminate:
			return fmt.Errorf("Failed to run within %v", timeout)
		}
	}
}

func updateSystemDNS(t *testing.T, dnsInfs []*winipcfg.IPAdapterAddresses) {
	testDNSAddr := netip.MustParseAddr(testSrvAddr)
	testDNSAddrIPv6 := netip.IPv6Unspecified()
	for _, addr := range dnsInfs {
		// Set IPv4 DNS
		err := addr.LUID.SetDNS(windows.AF_INET, []netip.Addr{testDNSAddr}, []string{})
		require.NoErrorf(t, err, "Failed setting IPv4 DNS server for: %v", addr.FriendlyName())
		// Set IPv6 DNS to unspecified so DNS lookup will not be bypassed
		err = addr.LUID.SetDNS(windows.AF_INET6, []netip.Addr{testDNSAddrIPv6}, []string{})
		require.NoErrorf(t, err, "Failed setting IPv6 DNS server for: %v", addr.FriendlyName())
	}
}

func restoreSystemDNS(t *testing.T, addrs []*winipcfg.IPAdapterAddresses, cachedAddrs map[string][]netip.Addr) {
	t.Log("Restoring DNS servers back to the original state")
	for _, addr := range addrs {
		err := addr.LUID.FlushDNS(windows.AF_INET)
		require.NoErrorf(t, err, "Failed to flush DNS for IPv4 addrs for: %v", addr.FriendlyName())
		err = addr.LUID.FlushDNS(windows.AF_INET6)
		require.NoErrorf(t, err, "Failed to flush DNS for IPv6 addrs for: %v", addr.FriendlyName())
	}
}

func downloadWSLTarball(path, url string) error {
	resp, err := http.Get(url) // nolint:gosec // wsl-distro release URL
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	return nil
}
