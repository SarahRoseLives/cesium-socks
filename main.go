package main

import (
        "bufio"
        "encoding/binary"
        "errors"
        "flag"
        "fmt"
        "io"
        "context"
        "log"
        "net"
        "os"
        "strings"
        "time"

        "github.com/TransIRC/cesiumlib"
        "github.com/armon/go-socks5"
)

type ServerConfig struct {
        ListenAddr   string
        TunnelDomain string
        Password     string
}

func parseConfig(filename string) (*ServerConfig, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        config := &ServerConfig{}
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                parts := strings.SplitN(line, "=", 2)
                if len(parts) != 2 {
                        continue
                }
                key := strings.TrimSpace(parts[0])
                value := strings.TrimSpace(parts[1])
                switch key {
                case "listen_addr":
                        config.ListenAddr = value
                case "tunnel_domain":
                        config.TunnelDomain = value
                case "password":
                        config.Password = value
                }
        }
        if config.ListenAddr == "" || config.TunnelDomain == "" || config.Password == "" {
                return nil, errors.New("missing required configuration values (listen_addr, tunnel_domain, password)")
        }
        return config, nil
}

type ClientConfig struct {
        DNSServerAddr  string
        TunnelDomain   string
        TunnelPassword string
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
    if targetLen == 0 || targetLen > 4096 {
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
func runServer(config *ServerConfig) error {
        addr, err := net.ResolveUDPAddr("udp", config.ListenAddr)
        if err != nil {
                return fmt.Errorf("resolve error: %w", err)
        }
        udpConn, err := net.ListenUDP("udp", addr)
        if err != nil {
                return fmt.Errorf("listen error: %w", err)
        }
        defer udpConn.Close()
        log.Printf("DNS tunneling server started on %s for domain %s", config.ListenAddr, config.TunnelDomain)
        return cesiumlib.AcceptServerDnsTunnelConns(udpConn, config.TunnelDomain, config.Password, func(conn net.Conn) {
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
                // Relay data in both directions, closing both conns when either ends
                done := make(chan struct{}, 2)
                go func() {
                        io.Copy(target, conn)
                        target.Close()
                        conn.Close()
                        done <- struct{}{}
                }()
                go func() {
                        io.Copy(conn, target)
                        target.Close()
                        conn.Close()
                        done <- struct{}{}
                }()
                <-done // Wait for one side to finish, then exit handler (both connections closed)
        })
}

// Client: SOCKS5 dialer opens DNS tunnel, sends target, returns tunnel conn
func runClient(config *ClientConfig) error {
        dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
                conn, err := cesiumlib.NewDnsTunnelConn(config.DNSServerAddr, config.TunnelDomain, config.TunnelPassword)
                if err != nil {
                        return nil, err
                }
                wrappedConn := &tcpLikeConn{Conn: conn}
                // Send the SOCKS5 target address as first message
                if err := sendTargetAddress(wrappedConn, addr); err != nil {
                        wrappedConn.Close()
                        return nil, err
                }
                return wrappedConn, nil
        }
        socksConf := &socks5.Config{
                Dial: dialer,
        }
        s5server, err := socks5.New(socksConf)
        if err != nil {
                return fmt.Errorf("failed to create SOCKS5 server: %w", err)
        }
        fmt.Println("SOCKS5 tunnel client started on 127.0.0.1:1080")
        fmt.Println("Configure your applications to use this as a SOCKS5 proxy (no UDP, only TCP supported)")
        fmt.Println("Username/password authentication is not enabled")
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
        configFile := flag.String("config", "config.conf", "Configuration file (server mode only)")
        flag.Parse()

        if *serverMode {
                config, err := parseConfig(*configFile)
                if err != nil {
                        log.Fatalf("Failed to parse config: %v", err)
                }
                if err := runServer(config); err != nil {
                        log.Fatalf("Server error: %v", err)
                }
        } else {
                password, err := promptPassword()
                if err != nil {
                        log.Fatalf("Failed to read password: %v", err)
                }
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
                clientConfig := &ClientConfig{
                        DNSServerAddr:  "144.202.58.207:5353",
                        TunnelDomain:   "dns.transirc.chat",
                        TunnelPassword: password,
                }
                if err := runClient(clientConfig); err != nil {
                        log.Fatalf("Client error: %v", err)
                }
        }
}
