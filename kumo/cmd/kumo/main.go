package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"net/http"
	"time"

	"github.com/kumo-ai/kumo/internal/analyzer"
	"github.com/kumo-ai/kumo/internal/demo"
	"github.com/kumo-ai/kumo/internal/export"
	"github.com/kumo-ai/kumo/internal/config"
	"github.com/kumo-ai/kumo/internal/eval"
	"github.com/kumo-ai/kumo/internal/logger"
	"github.com/kumo-ai/kumo/internal/notify"
	policyPkg "github.com/kumo-ai/kumo/internal/policy"
	"github.com/kumo-ai/kumo/internal/tui"
	"github.com/kumo-ai/kumo/internal/proxy"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "kumo",
		Short: "AI agent security proxy",
		Long:  "Kumo is a TLS-intercepting HTTP proxy that observes, secures, and manages AI agent traffic.",
	}

	root.AddCommand(initCmd())
	root.AddCommand(serveCmd())
	root.AddCommand(summarizeCmd())
	root.AddCommand(replayCmd())
	root.AddCommand(exportCmd())
	root.AddCommand(diffCmd())
	root.AddCommand(demoCmd())
	root.AddCommand(tuiCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(doctorCmd())
	root.AddCommand(versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate CA certificate and default config",
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir = expandHome(dataDir)
			if err := os.MkdirAll(dataDir, 0755); err != nil {
				return fmt.Errorf("Error: cannot create directory %s\nCause: %v\nFix: check permissions on parent directory", dataDir, err)
			}

			// Generate CA
			cert, _, err := proxy.LoadOrGenerateCA(dataDir)
			if err != nil {
				return fmt.Errorf("Error: cannot generate CA certificate\nCause: %v\nFix: check write permissions in %s", err, dataDir)
			}

			// Write default config
			cfgPath := filepath.Join(dataDir, "config.yaml")
			if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
				if err := config.WriteDefault(cfgPath); err != nil {
					return fmt.Errorf("Error: cannot write config\nCause: %v", err)
				}
				fmt.Printf("Generated config: %s\n", cfgPath)
			} else {
				fmt.Printf("Config already exists: %s\n", cfgPath)
			}

			certPath := filepath.Join(dataDir, "ca.pem")
			fmt.Printf("Generated CA certificate: %s\n", certPath)
			fmt.Printf("CA valid until: %s\n", cert.NotAfter.Format("2006-01-02"))
			fmt.Println()
			fmt.Println("Trust the CA cert on your agent:")
			fmt.Printf("  export SSL_CERT_FILE=%s\n", certPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", "~/.kumo", "Directory for CA certs and config")
	return cmd
}

func serveCmd() *cobra.Command {
	var (
		mode       string
		port       string
		dataDir    string
		policyFile string
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the proxy server",
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir = expandHome(dataDir)

			// Validate mode
			if mode != "observe" && mode != "enforce" {
				return fmt.Errorf("Error: invalid mode %q\nCause: mode must be 'observe' or 'enforce'\nFix: kumo serve --mode observe", mode)
			}

			// Enforce mode requires --policy
			if mode == "enforce" && policyFile == "" {
				return fmt.Errorf("Error: --policy is required in enforce mode\nCause: enforce mode needs a policy file to evaluate requests against\nFix: kumo serve --mode enforce --policy policy.yaml")
			}

			// Load or generate CA
			caCert, caKey, err := proxy.LoadOrGenerateCA(dataDir)
			if err != nil {
				return fmt.Errorf("Error: cannot load CA certificate\nCause: %v\nFix: run 'kumo init' first, or check permissions in %s", err, dataDir)
			}

			// Set up logger
			logDir := filepath.Join(dataDir, "logs")
			trafficLogger, err := logger.New(logDir)
			if err != nil {
				return fmt.Errorf("Error: cannot create traffic logger\nCause: %v\nFix: check write permissions in %s", err, logDir)
			}

			// Load policy engine for enforce mode
			var engine proxy.PolicyEngine
			if mode == "enforce" {
				pol, err := policyPkg.LoadPolicy(policyFile)
				if err != nil {
					return fmt.Errorf("Error: cannot load policy file\nCause: %v\nFix: check that %s exists and is valid YAML", err, policyFile)
				}
				eng, err := policyPkg.NewEngine(pol)
				if err != nil {
					return fmt.Errorf("Error: cannot compile policy rules\nCause: %v\nFix: check glob patterns in %s", err, policyFile)
				}
				engine = eng
				fmt.Printf("Policy: %s (%d fast rules)\n", pol.Name, eng.RuleCount())
			}

			// Create handler
			handler := proxy.NewHandler(engine, trafficLogger, mode)
			handler.SetVerbose(verbose)

			// Set up ban manager and webhook notifier for enforce mode
			if mode == "enforce" {
				pol, _ := policyPkg.LoadPolicy(policyFile)
				if pol != nil {
					banMgr := policyPkg.NewBanManager(pol.Ban)
					handler.SetBanChecker(banMgr)
				}

				// Load config for webhook URL
				cfgPath := filepath.Join(dataDir, "config.yaml")
				if cfg, err := config.Load(cfgPath); err == nil && cfg.Notify.WebhookURL != "" {
					notifier := notify.NewWebhookNotifier(cfg.Notify.WebhookURL, cfg.Notify.On)
					handler.SetNotifier(notifier)
					fmt.Printf("Webhook notifications: %s\n", cfg.Notify.WebhookURL)
				}
			}

			// Create and start proxy
			addr := ":" + port
			server := proxy.NewServer(addr, caCert, caKey, handler)
			if verbose {
				server.SetVerbose(true)
			}

			fmt.Printf("Kumo proxy listening on %s (%s mode)\n", addr, mode)
			if mode == "observe" {
				fmt.Printf("Logging traffic to %s\n", logDir)
			}

			// Start health check endpoint
			go func() {
				healthAddr := ":9091"
				mux := http.NewServeMux()
				mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("ok"))
				})
				log.Printf("Health check on %s/healthz", healthAddr)
				http.ListenAndServe(healthAddr, mux)
			}()

			// Graceful shutdown: flush logs on SIGTERM/SIGINT (Docker stop)
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()

			errCh := make(chan error, 1)
			go func() { errCh <- server.ListenAndServe() }()

			select {
			case err := <-errCh:
				trafficLogger.Flush()
				return err
			case <-ctx.Done():
				log.Println("Shutting down, flushing logs...")
				trafficLogger.Flush()
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "observe", "Proxy mode: observe or enforce")
	cmd.Flags().StringVar(&port, "port", "8080", "Listen port")
	cmd.Flags().StringVar(&dataDir, "data-dir", "~/.kumo", "Directory for CA certs and config")
	cmd.Flags().StringVar(&policyFile, "policy", "", "Policy file (required for enforce mode)")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Print every request to stdout")
	return cmd
}

func summarizeCmd() *cobra.Command {
	var (
		output     string
		maxSamples int
	)

	cmd := &cobra.Command{
		Use:   "summarize <log-dir>",
		Short: "Auto-generate a security policy from observed traffic",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logDir := args[0]
			if output == "" {
				output = "policy.yaml"
			}
			return analyzer.Summarize(logDir, output, maxSamples)
		},
	}

	cmd.Flags().StringVar(&output, "output", "policy.yaml", "Output policy file path")
	cmd.Flags().IntVar(&maxSamples, "max-samples", 200, "Max requests to sample per URL pattern")
	return cmd
}

func exportCmd() *cobra.Command {
	var (
		format string
		output string
	)

	cmd := &cobra.Command{
		Use:   "export <log-dir>",
		Short: "Export observed traffic as OpenAPI spec",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "openapi" {
				return fmt.Errorf("Error: unsupported format %q\nFix: use --format openapi", format)
			}
			return export.ExportOpenAPI(args[0], output)
		},
	}

	cmd.Flags().StringVar(&format, "format", "openapi", "Export format (openapi)")
	cmd.Flags().StringVar(&output, "output", "openapi.yaml", "Output file path")
	return cmd
}

func diffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <policy-a> <policy-b>",
		Short: "Compare two policy files",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			polA, err := policyPkg.LoadPolicy(args[0])
			if err != nil {
				return fmt.Errorf("Error: cannot load %s\nCause: %v", args[0], err)
			}
			polB, err := policyPkg.LoadPolicy(args[1])
			if err != nil {
				return fmt.Errorf("Error: cannot load %s\nCause: %v", args[1], err)
			}

			// Compare rules
			rulesA := make(map[string]string)
			for _, r := range polA.Rules.Fast {
				rulesA[r.Name] = r.Action
			}
			rulesB := make(map[string]string)
			for _, r := range polB.Rules.Fast {
				rulesB[r.Name] = r.Action
			}

			fmt.Printf("Policy A: %s (%d rules)\n", polA.Name, len(polA.Rules.Fast))
			fmt.Printf("Policy B: %s (%d rules)\n", polB.Name, len(polB.Rules.Fast))
			fmt.Println()

			// Added in B
			for name, action := range rulesB {
				if _, ok := rulesA[name]; !ok {
					fmt.Printf("  + %s (%s) — new in B\n", name, action)
				}
			}
			// Removed from A
			for name, action := range rulesA {
				if _, ok := rulesB[name]; !ok {
					fmt.Printf("  - %s (%s) — removed in B\n", name, action)
				}
			}
			// Changed
			for name, actionA := range rulesA {
				if actionB, ok := rulesB[name]; ok && actionA != actionB {
					fmt.Printf("  ~ %s: %s → %s\n", name, actionA, actionB)
				}
			}

			// Default change
			if polA.Rules.Default != polB.Rules.Default {
				fmt.Printf("\n  Default: %s → %s\n", polA.Rules.Default, polB.Rules.Default)
			}

			return nil
		},
	}
}

func replayCmd() *cobra.Command {
	var policyFile string

	cmd := &cobra.Command{
		Use:   "replay <log-file>",
		Short: "Replay traffic against a policy to evaluate and refine it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logFile := args[0]
			summary, err := eval.Replay(logFile, policyFile)
			if err != nil {
				return err
			}
			eval.PrintSummary(summary)

			// Write report
			reportPath := fmt.Sprintf("./reports/eval-%s.md", time.Now().Format("2006-01-02"))
			if err := eval.WriteReport(summary, reportPath); err != nil {
				log.Printf("WARNING: could not write report: %v", err)
			} else {
				fmt.Printf("Eval report: %s\n", reportPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&policyFile, "policy", "", "Policy file to evaluate against (required)")
	cmd.MarkFlagRequired("policy")
	return cmd
}

func demoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "demo",
		Short: "Run a self-contained demo showing the full observe → enforce loop",
		RunE: func(cmd *cobra.Command, args []string) error {
			return demo.Run()
		},
	}
}

func tuiCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Open the terminal dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir = expandHome(dataDir)
			logDir := filepath.Join(dataDir, "logs")
			return tui.Run(logDir)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", "~/.kumo", "Directory for CA certs and config")
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show proxy health and traffic summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if proxy is running by hitting healthz
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get("http://localhost:9091/healthz")
			if err != nil {
				fmt.Println("Kumo proxy: not running")
				return nil
			}
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Println("Kumo proxy: running")
			} else {
				fmt.Printf("Kumo proxy: unhealthy (status %d)\n", resp.StatusCode)
			}
			return nil
		},
	}
}

func doctorCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check Kumo setup and diagnose common issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir = expandHome(dataDir)
			issues := 0

			// Check CA cert
			fmt.Print("CA certificate... ")
			_, _, err := proxy.LoadCA(dataDir)
			if err != nil {
				fmt.Printf("MISSING\n  Fix: run 'kumo init'\n")
				issues++
			} else {
				fmt.Println("OK")
			}

			// Check config
			fmt.Print("Config file... ")
			cfgPath := filepath.Join(dataDir, "config.yaml")
			cfg, err := config.Load(cfgPath)
			if err != nil {
				fmt.Printf("MISSING or INVALID\n  Fix: run 'kumo init'\n")
				issues++
			} else {
				fmt.Println("OK")
				_ = cfg
			}

			// Check proxy connectivity
			fmt.Print("Proxy connectivity... ")
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get("http://localhost:9091/healthz")
			if err != nil {
				fmt.Println("NOT RUNNING")
				fmt.Println("  Fix: run 'kumo serve --mode observe'")
			} else {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					fmt.Println("OK")
				} else {
					fmt.Printf("UNHEALTHY (status %d)\n", resp.StatusCode)
					issues++
				}
			}

			// Check Anthropic API key (for summarize/judge)
			fmt.Print("Anthropic API key... ")
			if os.Getenv("ANTHROPIC_API_KEY") != "" {
				fmt.Println("SET")
			} else {
				fmt.Println("NOT SET")
				fmt.Println("  Fix: export ANTHROPIC_API_KEY=sk-ant-...")
				fmt.Println("  Note: only needed for 'kumo summarize' (LLM-powered mode)")
			}

			if issues == 0 {
				fmt.Println("\nAll checks passed.")
			} else {
				fmt.Printf("\n%d issue(s) found.\n", issues)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", "~/.kumo", "Directory for CA certs and config")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("kumo %s\n", version)
		},
	}
}

func expandHome(path string) string {
	if len(path) > 1 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Printf("WARNING: cannot expand ~: %v", err)
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
