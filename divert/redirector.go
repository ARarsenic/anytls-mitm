package divert

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/imgk/divert-go"
)

// PortRange defines an inclusive TCP port range [Start, End].
type PortRange struct {
	Start uint16
	End   uint16
}

// RedirectorConfig defines the configuration for the WinDivert TCP redirector.
type RedirectorConfig struct {
	Subnet     string // e.g. "192.168.137.0/24"
	ListenIP   string // e.g. "192.168.137.1"
	ListenPort uint16 // e.g. 10443
	PortRanges []PortRange
	NATTable   *NATTable
	Verbose    bool
}

// Redirector intercepts hotspot TCP traffic across both Network and Forward layers,
// performing seamless NAT redirection to the local proxy.
type Redirector struct {
	config        RedirectorConfig
	subnet        *net.IPNet
	listenIP      net.IP
	hotspotIfIdx  uint32
	natTable      *NATTable
	allPorts      bool
	targetPortSet map[uint16]bool
	netHandle     *divert.Handle
	fwdHandle     *divert.Handle
	stopChan      chan struct{}
}

// findInterfaceIndex dynamically resolves the OS network interface index for a given IP.
func findInterfaceIndex(targetIP net.IP) uint32 {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.To4() != nil && ipNet.IP.To4().Equal(targetIP) {
					return uint32(iface.Index)
				}
			}
		}
	}
	return 0
}

// NewRedirector initializes a Redirector.
func NewRedirector(cfg RedirectorConfig) (*Redirector, error) {
	_, ipNet, err := net.ParseCIDR(cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %q: %w", cfg.Subnet, err)
	}

	lip := net.ParseIP(cfg.ListenIP).To4()
	if lip == nil {
		return nil, fmt.Errorf("invalid listen IP (must be IPv4) %q", cfg.ListenIP)
	}

	if cfg.NATTable == nil {
		cfg.NATTable = NewNATTable()
	}

	ifIdx := findInterfaceIndex(lip)

	allPorts := false
	targetPortSet := make(map[uint16]bool)
	for _, pr := range cfg.PortRanges {
		if pr.Start == 1 && pr.End == 65535 {
			allPorts = true
			break
		}
		for p := pr.Start; p <= pr.End; p++ {
			targetPortSet[p] = true
			if p == 65535 {
				break
			}
		}
	}

	return &Redirector{
		config:        cfg,
		subnet:        ipNet,
		listenIP:      lip,
		hotspotIfIdx:  ifIdx,
		natTable:      cfg.NATTable,
		allPorts:      allPorts,
		targetPortSet: targetPortSet,
		stopChan:      make(chan struct{}),
	}, nil
}

func (r *Redirector) isTargetPort(dstPort uint16) bool {
	if dstPort == r.config.ListenPort {
		return false
	}
	if r.allPorts {
		return true
	}
	return r.targetPortSet[dstPort]
}

func (r *Redirector) buildPortFilter() string {
	if r.allPorts {
		return fmt.Sprintf("tcp.DstPort != %d", r.config.ListenPort)
	}
	var portConditions []string
	for _, pr := range r.config.PortRanges {
		if pr.Start == pr.End {
			portConditions = append(portConditions, fmt.Sprintf("tcp.DstPort == %d", pr.Start))
		} else {
			portConditions = append(portConditions, fmt.Sprintf("(tcp.DstPort >= %d and tcp.DstPort <= %d)", pr.Start, pr.End))
		}
	}
	portCondStr := strings.Join(portConditions, " or ")
	if len(portConditions) > 1 {
		portCondStr = "(" + portCondStr + ")"
	}
	return portCondStr
}

// Start opens WinDivert handles on both Network and Forward layers.
func (r *Redirector) Start(ctx context.Context) error {
	log.Printf("[Divert] Hotspot adapter (%s) interface index resolved as: %d", r.listenIP.String(), r.hotspotIfIdx)
	portCondStr := r.buildPortFilter()

	// 1. Forward Layer Handle: Captures packets routed/forwarded through Windows Hotspot (ICS)
	fwdFilter := fmt.Sprintf("tcp and %s", portCondStr)
	log.Printf("[Divert] Opening Forward layer handle with filter: %s", fwdFilter)
	fwdHandle, err := divert.Open(fwdFilter, divert.LayerNetworkForward, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("[Divert] Warning: Failed to open Forward layer handle (%v), proceeding with Network layer only", err)
	} else {
		r.fwdHandle = fwdHandle
	}

	// 2. Network Layer Handle: Captures local traffic & handles replies from proxy
	netFilter := fmt.Sprintf(
		"tcp and (%s or (tcp.SrcPort == %d and ip.SrcAddr == %s))",
		portCondStr, r.config.ListenPort, r.listenIP.String(),
	)
	log.Printf("[Divert] Opening Network layer handle with filter: %s", netFilter)
	netHandle, err := divert.Open(netFilter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		if r.fwdHandle != nil {
			r.fwdHandle.Close()
		}
		return fmt.Errorf("failed to open Network layer handle: %w", err)
	}
	r.netHandle = netHandle

	go func() {
		<-ctx.Done()
		r.Stop()
	}()

	if r.fwdHandle != nil {
		go r.forwardLoop()
	}
	go r.networkLoop()

	return nil
}

// Stop closes all WinDivert handles and terminates worker loops.
func (r *Redirector) Stop() {
	select {
	case <-r.stopChan:
		return
	default:
		close(r.stopChan)
	}

	if r.fwdHandle != nil {
		r.fwdHandle.Close()
	}
	if r.netHandle != nil {
		r.netHandle.Close()
	}
}

// formatTCPPacket extracts flags, seq, ack, and payload length for network debugging.
func formatTCPPacket(buf []byte, ihl int) (string, int) {
	if len(buf) < ihl+20 {
		return "invalid", 0
	}
	srcPort := binary.BigEndian.Uint16(buf[ihl : ihl+2])
	dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
	seq := binary.BigEndian.Uint32(buf[ihl+4 : ihl+8])
	ack := binary.BigEndian.Uint32(buf[ihl+8 : ihl+12])
	tcpHdrLen := int(buf[ihl+12]>>4) * 4
	flags := buf[ihl+13]
	payloadLen := len(buf) - ihl - tcpHdrLen
	if payloadLen < 0 {
		payloadLen = 0
	}

	var f []string
	if flags&0x02 != 0 {
		f = append(f, "SYN")
	}
	if flags&0x10 != 0 {
		f = append(f, "ACK")
	}
	if flags&0x08 != 0 {
		f = append(f, "PSH")
	}
	if flags&0x01 != 0 {
		f = append(f, "FIN")
	}
	if flags&0x04 != 0 {
		f = append(f, "RST")
	}

	return fmt.Sprintf("%d->%d [%s] Seq=%d Ack=%d DataLen=%d",
		srcPort, dstPort, strings.Join(f, "|"), seq, ack, payloadLen), payloadLen
}

// forwardLoop handles packets traversing the Windows Hotspot routing engine (LayerNetworkForward).
func (r *Redirector) forwardLoop() {
	buf := make([]byte, 65535)
	var addr divert.Address

	for {
		select {
		case <-r.stopChan:
			return
		default:
		}

		n, err := r.fwdHandle.Recv(buf, &addr)
		if err != nil {
			select {
			case <-r.stopChan:
				return
			default:
				log.Printf("[Divert-Fwd] Recv error: %v", err)
				return
			}
		}

		pktLen := int(n)
		if pktLen < 40 || buf[0]>>4 != 4 || buf[9] != 6 {
			r.fwdHandle.Send(buf[:n], &addr)
			continue
		}

		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || pktLen < ihl+20 {
			r.fwdHandle.Send(buf[:n], &addr)
			continue
		}

		srcIP := net.IP(buf[12:16])
		dstIP := net.IP(buf[16:20])
		srcPort := binary.BigEndian.Uint16(buf[ihl : ihl+2])
		dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])

		// Match hotspot client traffic to target port
		if r.subnet.Contains(srcIP) && !srcIP.Equal(r.listenIP) && r.isTargetPort(dstPort) {
			clientKey := net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort)))
			origDst := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))

			r.natTable.Set(clientKey, origDst)

			tcpFlags := buf[ihl+13]
			isSYN := (tcpFlags&0x02 != 0) && (tcpFlags&0x10 == 0)
			isRST := (tcpFlags & 0x04) != 0
			isFIN := (tcpFlags & 0x01) != 0

			pktDesc, payloadLen := formatTCPPacket(buf[:n], ihl)
			if isRST {
				log.Printf("[Divert-RST] Hotspot Client sent TCP RST! %s -> %s | %s",
					clientKey, origDst, pktDesc)
			} else if isSYN {
				log.Printf("[Divert-Fwd] Intercepted Hotspot Client TCP SYN: %s -> %s (redirecting to proxy %s:%d, captured IfIdx=%d)",
					clientKey, origDst, r.listenIP, r.config.ListenPort, addr.Network().InterfaceIndex)
			} else if isFIN || payloadLen > 0 || r.config.Verbose {
				log.Printf("[Divert-Fwd] IN %s -> %s | %s",
					clientKey, origDst, pktDesc)
			}

			// Rewrite destination IP and port to local proxy listener
			copy(buf[16:20], r.listenIP.To4())
			binary.BigEndian.PutUint16(buf[ihl+2:ihl+4], r.config.ListenPort)

			// Clean Address initialized for LayerNetwork Inbound
			var netAddr divert.Address
			netAddr.SetLayer(divert.LayerNetwork)
			netAddr.Flags = 0x08 // Impostor = true, Outbound = false (Inbound to local stack)

			// Crucial: deliver on the hotspot virtual adapter interface so Windows routing accepts it
			if r.hotspotIfIdx > 0 {
				netAddr.Network().InterfaceIndex = r.hotspotIfIdx
			} else {
				netAddr.Network().InterfaceIndex = addr.Network().InterfaceIndex
			}
			netAddr.Network().SubInterfaceIndex = 0

			divert.CalcChecksums(buf[:n], &netAddr, 0)

			// Inject into local network stack so local proxy listener receives it
			nSent, err := r.netHandle.Send(buf[:n], &netAddr)
			if err != nil {
				if r.config.Verbose {
					log.Printf("[Divert-Forward] Error reinjecting to local stack on ifIdx=%d: %v",
						netAddr.Network().InterfaceIndex, err)
				}
			} else if isSYN && r.config.Verbose {
				log.Printf("[Divert-Forward] Successfully reinjected SYN to local stack on ifIdx=%d (%d bytes)",
					netAddr.Network().InterfaceIndex, nSent)
			}
			continue
		}

		// Passthrough
		r.fwdHandle.Send(buf[:n], &addr)
	}
}

// networkLoop handles local traffic & replies from the proxy listener (LayerNetwork).
func (r *Redirector) networkLoop() {
	buf := make([]byte, 65535)
	var addr divert.Address

	for {
		select {
		case <-r.stopChan:
			return
		default:
		}

		n, err := r.netHandle.Recv(buf, &addr)
		if err != nil {
			select {
			case <-r.stopChan:
				return
			default:
				log.Printf("[Divert-Net] Recv error: %v", err)
				return
			}
		}

		pktLen := int(n)
		if pktLen < 40 || buf[0]>>4 != 4 || buf[9] != 6 {
			r.netHandle.Send(buf[:n], &addr)
			continue
		}

		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || pktLen < ihl+20 {
			r.netHandle.Send(buf[:n], &addr)
			continue
		}

		srcIP := net.IP(buf[12:16])
		dstIP := net.IP(buf[16:20])
		srcPort := binary.BigEndian.Uint16(buf[ihl : ihl+2])
		dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])

		// Case 1: Client inbound packet received at Network layer directly
		if r.subnet.Contains(srcIP) && !srcIP.Equal(r.listenIP) && r.isTargetPort(dstPort) {
			clientKey := net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort)))
			origDst := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))

			r.natTable.Set(clientKey, origDst)

			tcpFlags := buf[ihl+13]
			isSYN := (tcpFlags&0x02 != 0) && (tcpFlags&0x10 == 0)
			isRST := (tcpFlags & 0x04) != 0
			isFIN := (tcpFlags & 0x01) != 0

			pktDesc, payloadLen := formatTCPPacket(buf[:n], ihl)
			if isRST {
				log.Printf("[Divert-RST] Hotspot Client sent TCP RST (Net)! %s -> %s | %s",
					clientKey, origDst, pktDesc)
			} else if isSYN {
				log.Printf("[Divert-Net] Intercepted Hotspot Client TCP SYN: %s -> %s (redirecting to proxy %s:%d)",
					clientKey, origDst, r.listenIP, r.config.ListenPort)
			} else if isFIN || payloadLen > 0 || r.config.Verbose {
				log.Printf("[Divert-Net] IN %s -> %s | %s",
					clientKey, origDst, pktDesc)
			}

			copy(buf[16:20], r.listenIP.To4())
			binary.BigEndian.PutUint16(buf[ihl+2:ihl+4], r.config.ListenPort)

			addr.Flags &= ^uint8(0x02) // Inbound
			addr.Flags |= 0x08         // Impostor

			divert.CalcChecksums(buf[:n], &addr, 0)
			if _, err := r.netHandle.Send(buf[:n], &addr); err != nil && r.config.Verbose {
				log.Printf("[Divert-Net] Failed to reinject inbound: %v", err)
			}
			continue
		}

		// Case 2: Outbound reply from Local Proxy listener back to Hotspot Client
		if srcPort == r.config.ListenPort && r.subnet.Contains(dstIP) {
			clientKey := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))
			origDst, found := r.natTable.Get(clientKey)
			if found {
				origHost, origPortStr, err := net.SplitHostPort(origDst)
				if err == nil {
					origIP := net.ParseIP(origHost).To4()
					origPortNum, _ := strconv.Atoi(origPortStr)

					if origIP != nil && origPortNum > 0 {
						// Rewrite source IP & port back to original destination server
						copy(buf[12:16], origIP)
						binary.BigEndian.PutUint16(buf[ihl:ihl+2], uint16(origPortNum))

						addr.Flags |= 0x02 // Outbound
						addr.Flags |= 0x08 // Impostor

						tcpFlags := buf[ihl+13]
						isRST := (tcpFlags & 0x04) != 0
						isFIN := (tcpFlags & 0x01) != 0

						pktDesc, payloadLen := formatTCPPacket(buf[:n], ihl)
						if isRST {
							log.Printf("[Divert-RST] Windows Proxy sent TCP RST! %s:%d -> %s | %s",
								origHost, origPortNum, clientKey, pktDesc)
						} else if tcpFlags&0x12 == 0x12 {
							log.Printf("[Divert-Net] Relaying SYN-ACK reply: %s:%d -> %s",
								origHost, origPortNum, clientKey)
						} else if isFIN || payloadLen > 0 || r.config.Verbose {
							log.Printf("[Divert-Net] OUT %s:%d -> %s | %s",
								origHost, origPortNum, clientKey, pktDesc)
						}

						divert.CalcChecksums(buf[:n], &addr, 0)
						if _, err := r.netHandle.Send(buf[:n], &addr); err != nil && r.config.Verbose {
							log.Printf("[Divert-Net] Failed to reinject outbound reply: %v", err)
						}
						continue
					}
				}
			} else {
				log.Printf("[Divert-Net-WARNING] Reply from proxy port %d to %s has NO NAT mapping in table! Packet will retain proxy IP %s",
					r.config.ListenPort, clientKey, r.listenIP)
			}
		}

		// Passthrough
		r.netHandle.Send(buf[:n], &addr)
	}
}
