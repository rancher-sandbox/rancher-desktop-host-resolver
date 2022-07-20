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
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/helper"
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/test/testdns"
)

var (
	// for now we use this maybe this can be an env var from test
	wslDistroName         = "host-resolver-e2e-test"
	wslTarballName        = "distro-0.21.tar"
	wslTarballURL         = "https://github.com/rancher-sandbox/rancher-desktop-wsl-distro/releases/download/v0.21/distro-0.21.tar"
	testSrvAddr           = "127.0.0.1"
	dnsPort               = "53"
	dnsHammerArecords     = "testA.csv"
	dnsHammerTxtRecords   = "testTXT.csv"
	dnsHammerCNAMERecords = "testCNAME.csv"
	tmpDir                string
	baseDomain            = "host-resolver-e2e-test"
)

func TestLookupARecords(t *testing.T) {
	t.Logf("Running DNS hammer A Record test process in WSL distribution [%v]", wslDistroName)
	runTestCmd := cmdExec(
		tmpDir,
		"wsl",
		"--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./test", "dnshammer",
		"--rr-type", fmt.Sprintf("A=%s", dnsHammerArecords))
	err := runTestCmd.Run()
	require.NoError(t, err, "Running dns hammer against the peer process failed")
	// TODO (Nino-K): figure out why killing dns hammer fails
	_ = runTestCmd.Process.Kill()
}

func TestLookupTXTRecords(t *testing.T) {
	t.Logf("Running DNS hammer TXT test process in WSL distribution [%v]", wslDistroName)
	runTestCmd := cmdExec(
		tmpDir,
		"wsl",
		"--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./test", "dnshammer",
		"--rr-type", fmt.Sprintf("TXT=%s", dnsHammerTxtRecords))
	err := runTestCmd.Run()
	require.NoError(t, err, "Running dns hammer against the peer process failed")
	// TODO (Nino-K): figure out why killing dns hammer fails
	_ = runTestCmd.Process.Kill()
}

func TestLookupCNAMERecords(t *testing.T) {
	t.Logf("Running DNS hammer CNAME test process in WSL distribution [%v]", wslDistroName)
	runTestCmd := cmdExec(
		tmpDir,
		"wsl",
		"--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./test", "dnshammer",
		"--rr-type", fmt.Sprintf("CNAME=%s", dnsHammerCNAMERecords))
	err := runTestCmd.Run()
	require.NoError(t, err, "Running dns hammer against the peer process failed")
	_ = runTestCmd.Process.Kill()
}

func TestMain(m *testing.M) {
	tmpDir = os.TempDir()

	logrus.Info("Building host-resolver host binary")
	err := buildBinaries("../../...", "windows", tmpDir)
	requireNoErrorf(err, "Failed building host-resolver.exe: %v", err)

	logrus.Info("Building host-resolver peer binary")
	err = buildBinaries("../../...", "linux", tmpDir)
	requireNoErrorf(err, "Failed building host-resolver: %v", err)

	logrus.Info("Building DNS hammer binary")
	err = buildBinaries("../...", "linux", tmpDir)
	requireNoErrorf(err, "Failed building dnsHammer: %v", err)

	logrus.Info("Generating DNS hammer test A records")
	aRecords := generateArecords(100, baseDomain)
	err = writeDNSHammerFile(filepath.Join(tmpDir, dnsHammerArecords), aRecords)
	requireNoErrorf(err, "Failed generating A record test data: %v", err)

	logrus.Info("Generating DNS hammer test TXT records")
	txtRecords := generateTXTrecords(100, baseDomain)
	err = writeDNSHammerFile(filepath.Join(tmpDir, dnsHammerTxtRecords), txtRecords)
	requireNoErrorf(err, "Failed generating TXT record test data")

	logrus.Info("Generating DNS hammer test CNAME records")
	cnameRecords := generateCNAMErecords(100, baseDomain)
	err = writeDNSHammerFile(filepath.Join(tmpDir, dnsHammerCNAMERecords), cnameRecords)
	requireNoErrorf(err, "Failed generating CNAME test data")

	logrus.Infof("Dowloading %v wsl distro tarball", wslTarballName)
	tarballPath := filepath.Join(tmpDir, wslTarballName)

	err = downloadFile(tarballPath, wslTarballURL)
	requireNoErrorf(err, "Failed to download wsl distro tarball: %v", err)

	logrus.Infof("Creating %v wsl distro", wslDistroName)
	installCmd := cmdExec(
		tmpDir,
		"wsl",
		"--import",
		wslDistroName,
		".",
		tarballPath)
	err = installCmd.Run()
	requireNoErrorf(err, "Failed to install distro %v", err)

	// It takes a long time to start a new distro,
	// 20 sec is a long time but that's actually how long
	// it takes to start a distro without any flakiness
	timeout := time.Second * 20
	tryInterval := time.Second * 2
	err = confirm(func() bool {
		// Run `wslpath` to see if the distribution is registered; this avoids
		// parsing the output of `wsl --list` to avoid having to handle UTF-16.
		out, err := cmdRunWithOutput("wsl", "--distribution", wslDistroName, "--exec", "/bin/wslpath", ".")
		if err != nil {
			return false
		}
		// We expect `wslpath` to output a single dot for the given command.
		return strings.TrimSpace(out) == "."
	}, tryInterval, timeout)
	requireNoErrorf(err, "Failed to check if %v wsl distro is running: %v", wslDistroName, err)

	dnsInfs, err := helper.GetDNSInterfaces()
	requireNoErrorf(err, "Failed getting DNS addrs associated to interfaces")

	logrus.Info("Updating network interfaces with test DNS server address")
	// Update the dns addrs to test server
	updateSystemDNS(testSrvAddr, dnsInfs)

	tcpHandler := &testdns.Handler{
		Truncate:     false,
		Arecords:     aRecords,
		TXTrecords:   txtRecords,
		CNAMErecords: cnameRecords,
	}

	udpHandler := &testdns.Handler{
		Truncate:     true,
		Arecords:     aRecords,
		TXTrecords:   txtRecords,
		CNAMErecords: cnameRecords,
	}

	testServer := testdns.Server{
		Addr:       testSrvAddr,
		TCPPort:    dnsPort,
		UDPPort:    dnsPort,
		TCPHandler: tcpHandler,
		UDPHandler: udpHandler,
	}
	logrus.Info("Starting test upstream DNS server")
	go testServer.Run()

	logrus.Infof("Starting host-resolver peer process in wsl [%v]", wslDistroName)
	peerCmd := cmdExec(
		tmpDir,
		"wsl", "--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./rancher-desktop-host-resolver", "vsock-peer")
	err = peerCmd.Start()
	requireNoErrorf(err, "Starting host-resolver peer process faild")

	logrus.Info("Starting host-resolver host process")
	resolverExecPath := filepath.Join(tmpDir, "rancher-desktop-host-resolver.exe")
	hostCmd := cmdExec(
		tmpDir,
		resolverExecPath, "vsock-host",
		"--upstream-servers", fmt.Sprintf("[%v]", testSrvAddr))
	err = hostCmd.Start()
	requireNoErrorf(err, "Starting host-resolver host process faild")

	logrus.Info("Confirming host-resolver peer process is up")
	peerCmdTimeout := time.Second * 10
	err = confirm(func() bool {
		p, err := os.FindProcess(peerCmd.Process.Pid)
		if err != nil {
			logrus.Infof("looking for host-resolver peer process PID: %v", err)
			return false
		}
		return p.Pid == peerCmd.Process.Pid
	}, tryInterval, peerCmdTimeout)
	requireNoErrorf(err, "failed to confirm host-resolver process is running")

	code := m.Run()

	// restore the system DNS servers to the original state
	restoreSystemDNS(dnsInfs)

	err = peerCmd.Process.Kill()
	requireNoErrorf(err, "Failed to stop host-resolver peer process: %v", err)

	err = hostCmd.Process.Kill()
	requireNoErrorf(err, "Failed to stop host-resolver host process: %v", err)

	logrus.Infof("Deleting %v wsl distro", wslDistroName)
	unregisterCmd := cmdExec("", "wsl", "--unregister", wslDistroName)
	err = unregisterCmd.Run()
	requireNoErrorf(err, "Failed to unregister distro %v", err)

	os.Remove(tmpDir)

	os.Exit(code)
}

func requireNoErrorf(err error, format string, args ...interface{}) {
	if err != nil {
		logrus.Fatalf(format, args...)
	}
}

// TODO (Nino-K): maybe this can be replaced by CI
func buildBinaries(path, goos, tmpDir string) error {
	buildCmd := exec.Command("go", "build", "-o", tmpDir, path)
	buildCmd.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", goos))
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	return buildCmd.Run()
}

func cmdRunWithOutput(command string, args ...string) (string, error) {
	var outBuf, errBuf bytes.Buffer
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

func updateSystemDNS(testSrvAddr string, dnsInfs []*winipcfg.IPAdapterAddresses) {
	testDNSAddr := netip.MustParseAddr(testSrvAddr)
	testDNSAddrIPv6 := netip.IPv6Unspecified()
	for _, addr := range dnsInfs {
		// Set IPv4 DNS
		err := addr.LUID.SetDNS(windows.AF_INET, []netip.Addr{testDNSAddr}, []string{})
		requireNoErrorf(err, "Failed setting IPv4 DNS server for: %v", addr.FriendlyName())
		// Set IPv6 DNS to unspecified so DNS lookup will not be bypassed
		err = addr.LUID.SetDNS(windows.AF_INET6, []netip.Addr{testDNSAddrIPv6}, []string{})
		requireNoErrorf(err, "Failed setting IPv6 DNS server for: %v", addr.FriendlyName())
	}
}

func restoreSystemDNS(addrs []*winipcfg.IPAdapterAddresses) {
	logrus.Info("Restoring DNS servers back to the original state")
	for _, addr := range addrs {
		err := addr.LUID.FlushDNS(windows.AF_INET)
		requireNoErrorf(err, "Failed to flush DNS for IPv4 addrs for: %v", addr.FriendlyName())
		err = addr.LUID.FlushDNS(windows.AF_INET6)
		requireNoErrorf(err, "Failed to flush DNS for IPv6 addrs for: %v", addr.FriendlyName())
	}
}

func downloadFile(path, url string) error {
	resp, err := http.Get(url)
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

func writeDNSHammerFile(path string, records map[string][]string) error {
	csvFile, err := os.Create(path)
	if err != nil {
		return err
	}
	csvWriter := csv.NewWriter(csvFile)

	var data [][]string
	for k, v := range records {
		row := append([]string{k}, v...)
		data = append(data, row)
	}
	return csvWriter.WriteAll(data)
}

func generateCNAMErecords(n int, domain string) map[string][]string {
	records := make(map[string][]string)
	for i := 1; i <= n; i++ {
		subDomain := strings.ToLower(randomTxt(rand.Intn(10-1) + 1))
		domain := fmt.Sprintf("%s-%d.test.", domain, i)
		records[subDomain+"."+domain] = []string{domain}
	}
	return records
}

func generateTXTrecords(n int, domain string) map[string][]string {
	records := make(map[string][]string)
	for i := 1; i <= n; i++ {
		records[fmt.Sprintf("%s-%d.test.", domain, i)] = generateTXT()
	}
	return records
}

func generateTXT() (txt []string) {
	record := randomTxt(rand.Intn(255-1) + 1)
	txt = append(txt, record)
	return txt
}

func randomTxt(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func generateArecords(n int, domain string) map[string][]string {
	records := make(map[string][]string)
	for i := 1; i <= n; i++ {
		records[fmt.Sprintf("%s-%d.test.", domain, i)] = generateIPs(rand.Intn(10-1) + 1)
	}
	return records
}

func generateIPs(n int) (ips []string) {
	for i := 1; i <= n; i++ {
		ips = append(ips, ipv4Address())
	}
	return ips
}

func ipv4Address() string {
	bit := func() int { return rand.Intn(256) }
	var b strings.Builder
	for i := 1; i <= 4; i++ {
		if i == 1 && bit() == 0 {
			fmt.Fprintf(&b, "%d.", 10)
			continue
		}
		if i == 4 {
			fmt.Fprintf(&b, "%d", bit())
			break
		}
		fmt.Fprintf(&b, "%d.", bit())
	}
	return b.String()
}
