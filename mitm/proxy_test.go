package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"anytls-hotspot-mitm/divert"
)

// Exercise the real proxy pipeline without installing or opening WinDivert.
// The upstream speaks first, then waits for a partial authentication request
// before letting the client send its settings frame.
func TestProxyRelayDoesNotWaitForInspection(t *testing.T) {
	p, err := NewProxy(ProxyConfig{NATTable: divert.NewNATTable()})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := p.certCloner.Clone(&x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"test.example"},
	}, "", "test.example")
	if err != nil {
		t.Fatal(err)
	}
	up, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, name := range []string{"cold certificate", "cached certificate"} {
		t.Run(name, func(t *testing.T) {
			serverDone := make(chan error, 1)
			go func() {
				c, err := up.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = c.Write([]byte("ready")); err == nil {
					b := make([]byte, 34)
					_, err = io.ReadFull(c, b)
					if err == nil && !bytes.Equal(b, make([]byte, 34)) {
						err = io.ErrUnexpectedEOF
					}
				}
				if err == nil {
					_, err = c.Write([]byte("auth received"))
				}
				if err == nil {
					_, err = io.ReadFull(c, make([]byte, 7))
				}
				if err == nil {
					_, err = c.Write([]byte("done"))
				}
				serverDone <- err
			}()
			proxyDone := make(chan struct{})
			go func() {
				defer close(proxyDone)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				p.natTable.Set(c.RemoteAddr().String(), up.Addr().String())
				p.handleConnection(c)
			}()
			client, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{
				InsecureSkipVerify: true, ServerName: "test.example", NextProtos: []string{"h2", "http/1.1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
				t.Fatalf("ALPN = %q", got)
			}
			read := func(want string) {
				t.Helper()
				b := make([]byte, len(want))
				if _, err := io.ReadFull(client, b); err != nil {
					t.Fatal(err)
				}
				if string(b) != want {
					t.Fatalf("received %q, want %q", b, want)
				}
			}
			read("ready")
			if _, err := client.Write(make([]byte, 34)); err != nil {
				t.Fatal(err)
			}
			read("auth received")
			if _, err := client.Write([]byte{CmdSettings, 0, 0, 0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			read("done")
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			client.Close()
			select {
			case <-proxyDone:
			case <-time.After(3 * time.Second):
				t.Fatal("proxy did not stop")
			}
		})
	}
}
