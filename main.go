package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/TransIRC/cesiumlib"
	"github.com/armon/go-socks5"
)

// Config holds all possible configuration values for both server and client
type Config struct {
	ListenAddr    string
	ListenPort    string
	TunnelDomain  string
	Password      string
	TunnelIP      string
	DNSServerAddr string // Derived from TunnelIP:ListenPort for client, or explicit
}

// parseConfig reads configuration from a file into the Config struct.
// It does not validate for completeness, only for parsing errors.
func parseConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %s: %w", filename, err)
	}
	defer file.Close()

	config := &Config{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("Warning: Skipping malformed config line: %s", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "listen_addr":
			config.ListenAddr = value
		case "listen_port":
			config.ListenPort = value
		case "tunnel_domain":
			config.TunnelDomain = value
		case "password":
			config.Password = value
		case "tunnel_ip":
			config.TunnelIP = value
		// Add more cases here if you introduce other config keys
		default:
			log.Printf("Warning: Unknown config key '%s' ignored", key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}
	return config, nil
}

// ---- TCP-like wrapper for net.Conn ----
type tcpLikeConn struct {
	net.Conn
}

func (c *tcpLikeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	}
}
func (c *tcpLikeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	}
}

// ---------------------------------------

// Protocol: [2 bytes len][target string][payload]
func sendTargetAddress(conn net.Conn, target string) error {
	if len(target) > 65535 {
		return errors.New("target address too long")
	}
	buf := make([]byte, 2+len(target))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(target)))
	copy(buf[2:], []byte(target))
	_, err := conn.Write(buf)
	return err
}

func receiveTargetAddress(conn net.Conn) (string, error) {
	remote := conn.RemoteAddr().String()
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("[%s] Error reading target address length: %v", remote, err)
		return "", err
	}
	targetLen := binary.BigEndian.Uint16(lenBuf)
	log.Printf("[%s] Target address length bytes: %x %x (value: %d)", remote, lenBuf[0], lenBuf[1], targetLen)
	if targetLen == 0 || targetLen > 4096 { // Max length for DNS labels is 253, but could be longer for other protocols
		log.Printf("[%s] Invalid target address length: %d (raw bytes: %x %x)", remote, targetLen, lenBuf[0], lenBuf[1])
		return "", errors.New("invalid target address length")
	}
	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(conn, targetBuf); err != nil {
		log.Printf("[%s] Error reading target address: %v", remote, err)
		return "", err
	}
	log.Printf("[%s] Received target address: %s", remote, string(targetBuf))
	return string(targetBuf), nil
}

// Server: Accept tunnel, read target, connect, relay
func runServer(cfg *Config) error {
	if cfg.ListenAddr == "" {
		return errors.New("server config: listen_addr is required")
	}
	if cfg.ListenPort == "" {
		return errors.New("server config: listen_port is required")
	}
	if cfg.TunnelDomain == "" {
		return errors.New("server config: tunnel_domain is required")
	}
	if cfg.Password == "" {
		return errors.New("server config: password is required")
	}
	// tunnel_ip is not strictly required for the server's listening part, but good for completeness/logging
	if cfg.TunnelIP == "" {
		log.Println("Warning: server config: tunnel_ip is recommended but not set.")
	}

	// FIX: Concatenate address and port correctly
	fullListenAddr := net.JoinHostPort(cfg.ListenAddr, cfg.ListenPort)
	addr, err := net.ResolveUDPAddr("udp", fullListenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen address error: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP error on %s: %w", fullListenAddr, err)
	}
	defer udpConn.Close()
	log.Printf("DNS tunneling server started on udp/%s for domain %s", fullListenAddr, cfg.TunnelDomain)

	return cesiumlib.AcceptServerDnsTunnelConns(udpConn, cfg.TunnelDomain, cfg.Password, func(conn net.Conn) {
		targetAddr, err := receiveTargetAddress(conn)
		if err != nil {
			log.Printf("Failed to receive target address: %v", err)
			conn.Close()
			return
		}
		target, err := net.Dial("tcp", targetAddr)
		if err != nil {
			log.Printf("Failed to connect to target %s: %v", targetAddr, err)
			conn.Close()
			return
		}
		log.Printf("Relaying connection from %s to %s", conn.RemoteAddr(), targetAddr)

		// Relay data in both directions, closing both conns when either ends
		done := make(chan struct{}, 2)
		go func() {
			_, err := io.Copy(target, conn)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("Error copying from tunnel to target: %v", err)
			}
			target.Close()
			conn.Close()
			done <- struct{}{}
		}()
		go func() {
			_, err := io.Copy(conn, target)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("Error copying from target to tunnel: %v", err)
			}
			target.Close()
			conn.Close()
			done <- struct{}{}
		}()
		<-done // Wait for one side to finish, then exit handler (both connections closed)
		log.Printf("Connection to %s via %s closed.", targetAddr, conn.RemoteAddr())
	})
}

// Client: SOCKS5 dialer opens DNS tunnel, sends target, returns tunnel conn
func runClient(cfg *Config) error {
	// Client specific config validation and derivation
	var dnsServerAddr string
	if cfg.DNSServerAddr != "" {
		dnsServerAddr = cfg.DNSServerAddr
	} else if cfg.TunnelIP != "" && cfg.ListenPort != "" {
		dnsServerAddr = net.JoinHostPort(cfg.TunnelIP, cfg.ListenPort)
	} else {
		log.Println("Warning: client config: DNSServerAddr, or TunnelIP and ListenPort, not found. Using default DNS server.")
		dnsServerAddr = "144.202.58.207:5353" // Fallback to hardcoded default
	}

	tunnelDomain := cfg.TunnelDomain
	if tunnelDomain == "" {
		log.Println("Warning: client config: tunnel_domain not found. Using default tunnel domain.")
		tunnelDomain = "dns.transirc.chat" // Fallback to hardcoded default
	}

	tunnelPassword := cfg.Password
	if tunnelPassword == "" {
		// If password is not in config, prompt for it
		var err error
		tunnelPassword, err = promptPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := cesiumlib.NewDnsTunnelConn(dnsServerAddr, tunnelDomain, tunnelPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to establish DNS tunnel: %w", err)
		}
		wrappedConn := &tcpLikeConn{Conn: conn}
		// Send the SOCKS5 target address as first message
		if err := sendTargetAddress(wrappedConn, addr); err != nil {
			wrappedConn.Close()
			return nil, fmt.Errorf("failed to send target address through tunnel: %w", err)
		}
		return wrappedConn, nil
	}

	socksConf := &socks5.Config{
		Dial: dialer,
		// No authentication needed for this simple SOCKS5 server
	}
	s5server, err := socks5.New(socksConf)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 server: %w", err)
	}
	fmt.Println("SOCKS5 tunnel client started on 127.0.0.1:1080")
	fmt.Println("Configure your applications to use this as a SOCKS5 proxy (no UDP, only TCP supported)")
	fmt.Println("Username/password authentication is not enabled via SOCKS5, but the tunnel itself uses a password.")
	return s5server.ListenAndServe("tcp", "127.0.0.1:1080")
}

func promptPassword() (string, error) {
	fmt.Print("Enter tunnel password: ")
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
}

func main() {
	serverMode := flag.Bool("server", false, "Run in server mode")
	configFile := flag.String("config", "config.conf", "Configuration file (used by both server and client)")
	flag.Parse()

	cfg, err := parseConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load or parse config file: %v", err)
	}

	// Override cesiumlib defaults with adjusted values for reliability
	coreConfig := cesiumlib.DefaultConfig()
	coreConfig.ClientRawChunkSize = 30
	log.Printf("Overriding cesium-core ClientRawChunkSize to: %d (adjusted for reliability)", coreConfig.ClientRawChunkSize)
	coreConfig.ReadPollInterval = 250 * time.Millisecond
	log.Printf("Overriding cesium-core ReadPollInterval to: %v", coreConfig.ReadPollInterval)
	coreConfig.AckTimeout = 3000 * time.Millisecond
	log.Printf("Overriding cesium-core AckTimeout to: %v", coreConfig.AckTimeout)
	coreConfig.WriteTimeout = 20 * time.Second
	log.Printf("Overriding cesium-core WriteTimeout to: %v", coreConfig.WriteTimeout)
	coreConfig.KeepaliveInterval = 10 * time.Second
	log.Printf("Overriding cesium-core KeepaliveInterval to: %v", coreConfig.KeepaliveInterval)
	cesiumlib.Configure(coreConfig)

	if *serverMode {
		log.Println("Starting in server mode...")
		if err := runServer(cfg); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		log.Println("Starting in client mode...")
		if err := runClient(cfg); err != nil {
			log.Fatalf("Client error: %v", err)
		}
	}
}
