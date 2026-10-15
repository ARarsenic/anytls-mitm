package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"anytls-hotspot-mitm/divert"
	"anytls-hotspot-mitm/mitm"

	"golang.org/x/sys/windows"
)

// checkAdminPrivileges verifies if the process is running with elevated Administrator privileges.
func checkAdminPrivileges() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

func parsePortRanges(portsStr string) ([]divert.PortRange, error) {
	portsStr = strings.TrimSpace(strings.ToLower(portsStr))
	if portsStr == "all" || portsStr == "1-65535" || portsStr == "*" {
		return []divert.PortRange{{Start: 1, End: 65535}}, nil
	}

	parts := strings.Split(portsStr, ",")
	var ranges []divert.PortRange
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			rangeParts := strings.Split(p, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range %q", p)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start <= 0 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %q", p)
			}
			ranges = append(ranges, divert.PortRange{Start: uint16(start), End: uint16(end)})
		} else {
			portNum, err := strconv.Atoi(p)
			if err != nil || portNum <= 0 || portNum > 65535 {
				return nil, fmt.Errorf("invalid port %q", p)
			}
			ranges = append(ranges, divert.PortRange{Start: uint16(portNum), End: uint16(portNum)})
		}
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}
	return ranges, nil
}

func main() {
	var (
		subnetStr    string
		listenIP     string
		listenPort   int
		portsStr     string
		whitelistTTL     int
		maxConns         int
		handshakeTimeout int
		inspectTimeout   int
		noDivert         bool
		verbose          bool
	)

	flag.StringVar(&subnetStr, "subnet", "192.168.137.0/24", "Windows Hotspot subnet CIDR")
	flag.StringVar(&listenIP, "listen-ip", "192.168.137.1", "Proxy listen IP (usually the Hotspot virtual adapter IP)")
	flag.IntVar(&listenPort, "listen-port", 10443, "Local TCP proxy listen port")
	flag.StringVar(&portsStr, "ports", "1-65535", "Target destination TCP ports or ranges to intercept (default 1-65535 for all ports, e.g. 1-65535, or 8443,443)")
	flag.IntVar(&whitelistTTL, "whitelist-ttl", 30, "Fail-open whitelist TTL in minutes for non-AnyTLS/strict-cert hosts")
	flag.IntVar(&maxConns, "max-conns", 2048, "Maximum concurrent TCP connections (DoS/Slowloris defense)")
	flag.IntVar(&handshakeTimeout, "handshake-timeout", 10, "TLS handshake timeout in seconds (Slowloris defense)")
	flag.IntVar(&inspectTimeout, "inspect-timeout", 15, "First-packet AnyTLS detection timeout in seconds")
	flag.BoolVar(&noDivert, "no-divert", false, "Run TCP proxy only without WinDivert packet redirection (for testing)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose detailed connection and stream debug logging")
	flag.Parse()

	log.Println("=============================================================")
	log.Println("     Lightweight AnyTLS Transparent Hotspot MITM Proxy       ")
	log.Println("=============================================================")

	if !noDivert && !checkAdminPrivileges() {
		log.Println("[FATAL] This application requires Administrator privileges to run WinDivert.")
		log.Println("Please right-click your terminal or binary and select 'Run as Administrator'.")
		os.Exit(1)
	}

	targetPortRanges, err := parsePortRanges(portsStr)
	if err != nil {
		log.Fatalf("[FATAL] Invalid -ports flag: %v", err)
	}

	if net.ParseIP(listenIP) == nil {
		log.Fatalf("[FATAL] Invalid -listen-ip flag: %s", listenIP)
	}

	if _, _, err := net.ParseCIDR(subnetStr); err != nil {
		log.Fatalf("[FATAL] Invalid -subnet flag: %v", err)
	}

	// Ensure Windows searches the executable's directory for WinDivert.dll
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		_ = windows.SetDllDirectory(exeDir)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Shared thread-safe NAT table (with TTL expiration & clean shutdown)
	natTable := divert.NewNATTable()
	defer natTable.Stop()

	// 1. Initialize & Start MITM Proxy
	proxyCfg := mitm.ProxyConfig{
		ListenIP:         listenIP,
		ListenPort:       uint16(listenPort),
		NATTable:         natTable,
		WhitelistTTL:     time.Duration(whitelistTTL) * time.Minute,
		Verbose:          verbose,
		MaxConns:         maxConns,
		MaxConnsPerIP:    128,
		HandshakeTimeout: time.Duration(handshakeTimeout) * time.Second,
		InspectTimeout:   time.Duration(inspectTimeout) * time.Second,
	}

	mitmProxy, err := mitm.NewProxy(proxyCfg)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize MITM proxy: %v", err)
	}

	if err := mitmProxy.Start(ctx); err != nil {
		log.Fatalf("[FATAL] Failed to start MITM proxy: %v", err)
	}
	defer mitmProxy.Stop()

	// 2. Initialize & Start WinDivert Redirector (if enabled)
	if !noDivert {
		redirectorCfg := divert.RedirectorConfig{
			Subnet:     subnetStr,
			ListenIP:   listenIP,
			ListenPort: uint16(listenPort),
			PortRanges: targetPortRanges,
			NATTable:   natTable,
			Verbose:    verbose,
		}

		redirector, err := divert.NewRedirector(redirectorCfg)
		if err != nil {
			log.Fatalf("[FATAL] Failed to initialize WinDivert redirector: %v", err)
		}

		if err := redirector.Start(ctx); err != nil {
			log.Fatalf("[FATAL] Failed to start WinDivert redirector: %v", err)
		}
		defer redirector.Stop()

		log.Printf("[Init] Intercepting subnet %s on ports %s -> %s:%d",
			subnetStr, portsStr, listenIP, listenPort)
	} else {
		log.Println("[Init] Running in proxy-only mode (-no-divert). WinDivert disabled.")
	}

	log.Println("[Init] MITM proxy is active. Press Ctrl+C to terminate.")
	<-ctx.Done()
	log.Println("[Shutdown] Stopping AnyTLS MITM proxy...")
}
