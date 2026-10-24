// Command serai runs either half of a Serai reverse tunnel.
//
//	serai edge   -c /etc/serai/edge.json      # the relay users connect to
//	serai origin -c /etc/serai/origin.json    # the host that owns the panel
//	serai keygen                              # a fresh pre-shared key
//	serai pin    -cert fullchain.pem          # the SPKI pin for a certificate
//	serai check  -c config.json               # validate without starting
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Mohammad858m/serai/internal/config"
	"github.com/Mohammad858m/serai/internal/pool"
	"github.com/Mohammad858m/serai/internal/relay"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "edge":
		err = runRole(config.RoleEdge, os.Args[2:])
	case "origin":
		err = runRole(config.RoleOrigin, os.Args[2:])
	case "keygen":
		err = keygen(os.Args[2:])
	case "pin":
		err = pinCmd(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("serai %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "serai: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "serai: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `serai - a reverse tunnel for panel-based proxies

Usage:
  serai edge   -c <config>   run the relay (the host users connect to)
  serai origin -c <config>   run the origin (the host with 3x-ui / Xray)
  serai check  -c <config>   validate a config and print what it will do
  serai keygen               print a fresh pre-shared key
  serai pin -cert <file>     print the SPKI pin for a certificate
  serai version              print the version

The origin dials the edge, so the origin needs no open port and the edge
never has to reach a filtered address.
`)
}

func runRole(want config.Role, args []string) error {
	fs := flag.NewFlagSet(string(want), flag.ExitOnError)
	path := fs.String("c", "", "path to the config file")
	_ = fs.Parse(args)

	if *path == "" {
		return errors.New("-c <config> is required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if cfg.Role != want {
		return fmt.Errorf("config declares role %q but was started as %q", cfg.Role, want)
	}

	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch want {
	case config.RoleEdge:
		e, err := relay.NewEdge(cfg, log)
		if err != nil {
			return err
		}
		go serveAdmin(ctx, cfg, log, func() any { return e.Sessions() })
		return e.Run(ctx)
	default:
		o, err := relay.NewOrigin(cfg, log)
		if err != nil {
			return err
		}
		go serveAdmin(ctx, cfg, log, func() any { return o.Set().Snapshot() })
		return o.Run(ctx)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("c", "", "path to the config file")
	_ = fs.Parse(args)

	if *path == "" {
		return errors.New("-c <config> is required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}

	fmt.Printf("role      %s\n", cfg.Role)
	fmt.Printf("name      %s\n", cfg.Name)
	fmt.Printf("profile   %s\n", cfg.Profile)
	fmt.Printf("shaping   %s\n", cfg.Obfs.Scope)
	fmt.Printf("carriers  %d\n", cfg.Tuning.Carriers)
	fmt.Printf("window    %d KiB per stream, max %d streams per carrier\n",
		cfg.Tuning.StreamWindow/1024, cfg.Tuning.MaxStreams)
	fmt.Printf("memory    %d MiB worst case buffered\n", cfg.MemoryCeiling()/(1<<20))

	if cfg.Role == config.RoleOrigin {
		fmt.Printf("\npaths\n")
		for _, p := range cfg.Edge.Paths {
			dest := p.Addr
			if dest == "" {
				dest = p.URL
			}
			fp := p.Fingerprint
			if fp == "" {
				fp = "go (fingerprintable)"
			}
			fmt.Printf("  %-10s %-40s role=%-9s weight=%d  tls=%s\n",
				p.Transport, dest, p.Role, p.Weight, fp)
		}
		fmt.Printf("\nforwards\n")
		for _, f := range cfg.Forwards {
			target := f.Target
			if target == "" {
				target = f.TargetHost + ":<same port>"
			}
			fmt.Printf("  %-14s %-8s ports=%-22s -> %-24s proxy_protocol=%d\n",
				f.Name, f.Proto, portSummary(f.Ports), target, f.ProxyProtocol)
			if len(f.SNI) > 0 {
				fmt.Printf("  %-14s sni: %s\n", "", strings.Join(f.SNI, ", "))
			}
		}
	} else {
		fmt.Printf("\nlisteners\n")
		fmt.Printf("  tcp  %s   (tunnel SNI %q, websocket %s)\n",
			cfg.Server.ControlAddr, cfg.Server.TunnelSNI, cfg.Server.WSPath)
		if cfg.Server.QUICAddr != "" {
			fmt.Printf("  udp  %s   (quic)\n", cfg.Server.QUICAddr)
		}
		fmt.Printf("  decoy %s\n", orDash(cfg.Server.DecoyUpstream))
		fmt.Printf("  allow_ports %s\n", orDash(cfg.Server.AllowPorts))
	}

	fmt.Printf("\nconfig is valid\n")
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func portSummary(ports []int) string {
	if len(ports) == 0 {
		return "(sni only)"
	}
	if len(ports) <= 4 {
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = fmt.Sprint(p)
		}
		return strings.Join(parts, ",")
	}
	sort.Ints(ports)
	return fmt.Sprintf("%d-%d (%d)", ports[0], ports[len(ports)-1], len(ports))
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	size := fs.Int("bytes", 32, "key length in bytes")
	_ = fs.Parse(args)

	if *size < 16 {
		return errors.New("use at least 16 bytes")
	}
	b := make([]byte, *size)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(b))
	return nil
}

func pinCmd(args []string) error {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	certFile := fs.String("cert", "", "PEM certificate file")
	_ = fs.Parse(args)

	if *certFile == "" {
		return errors.New("-cert <file> is required")
	}
	raw, err := os.ReadFile(*certFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return fmt.Errorf("%s: no PEM block found", *certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	fmt.Printf("sha256/%s\n", spkiPin(cert))
	return nil
}

// spkiPin hashes the certificate's public key, not the certificate itself, so
// a renewal that reuses the key pair does not invalidate a deployed pin.
func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// serveAdmin exposes health, status and Prometheus metrics on a loopback port.
// It is bound to localhost by default and must stay there: it reveals the
// tunnel's existence to anyone who can reach it.
func serveAdmin(ctx context.Context, cfg *config.Config, log *slog.Logger, snapshot func() any) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"version": version,
			"role":    cfg.Role,
			"name":    cfg.Name,
			"profile": cfg.Profile,
			"data":    snapshot(),
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		writeMetrics(w, cfg, snapshot())
	})

	srv := &http.Server{Addr: cfg.AdminAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Warn("admin endpoint unavailable", "addr", cfg.AdminAddr, "err", err)
	}
}

// writeMetrics renders the Prometheus text format by hand, which keeps the
// binary free of a metrics dependency for the handful of series worth having.
func writeMetrics(w http.ResponseWriter, cfg *config.Config, snap any) {
	fmt.Fprintf(w, "# HELP serai_up 1 when the process is running.\n")
	fmt.Fprintf(w, "# TYPE serai_up gauge\n")
	fmt.Fprintf(w, "serai_up{role=%q,name=%q} 1\n", cfg.Role, cfg.Name)

	emit := func(origin string, stats []pool.Stats) {
		for _, s := range stats {
			labels := fmt.Sprintf("origin=%q,path=%q,transport=%q", origin, s.Path, s.Transport)
			fmt.Fprintf(w, "serai_carrier_active_streams{%s} %d\n", labels, s.Active)
			fmt.Fprintf(w, "serai_carrier_streams_total{%s} %d\n", labels, s.Streams)
			fmt.Fprintf(w, "serai_carrier_bytes_in_total{%s} %d\n", labels, s.BytesIn)
			fmt.Fprintf(w, "serai_carrier_bytes_out_total{%s} %d\n", labels, s.BytesOut)
			fmt.Fprintf(w, "serai_carrier_failures_total{%s} %d\n", labels, s.Failures)
			fmt.Fprintf(w, "serai_carrier_open_latency_seconds{%s} %f\n", labels, s.Latency.Seconds())
			fmt.Fprintf(w, "serai_carrier_uptime_seconds{%s} %f\n", labels, s.Uptime.Seconds())
		}
	}

	fmt.Fprintf(w, "# TYPE serai_carrier_active_streams gauge\n")
	fmt.Fprintf(w, "# TYPE serai_carrier_streams_total counter\n")
	fmt.Fprintf(w, "# TYPE serai_carrier_bytes_in_total counter\n")
	fmt.Fprintf(w, "# TYPE serai_carrier_bytes_out_total counter\n")

	switch v := snap.(type) {
	case []pool.Stats:
		emit(cfg.Name, v)
	case map[string][]pool.Stats:
		origins := make([]string, 0, len(v))
		for k := range v {
			origins = append(origins, k)
		}
		sort.Strings(origins)
		for _, o := range origins {
			emit(o, v[o])
		}
		fmt.Fprintf(w, "# TYPE serai_sessions gauge\nserai_sessions %d\n", len(v))
	}
}
