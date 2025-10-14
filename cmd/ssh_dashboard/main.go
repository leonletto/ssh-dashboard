package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/alpindale/ssh-dashboard/internal"
	"github.com/alpindale/ssh-dashboard/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
)

func validateInterval(seconds float64) time.Duration {
	if seconds < 0.01 || seconds > 3600 {
		return 0
	}
	return time.Duration(seconds * float64(time.Second))
}

func main() {
	var showVersion bool

	flag.Usage = func() {
		// HACK: make it look like python's argparse
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -n, --interval float  Update interval in seconds (default: 5, or SSH_DASHBOARD_INTERVAL env var)\n")
		fmt.Fprintf(os.Stderr, "  --host string         Connect directly to specified host from SSH config\n")
		fmt.Fprintf(os.Stderr, "  -v, --version         Show version information\n")
		fmt.Fprintf(os.Stderr, "  -h, --help            Show this help message\n")
	}

	var updateIntervalVal float64
	var hostName string
	flag.Float64Var(&updateIntervalVal, "n", 0, "")
	flag.Float64Var(&updateIntervalVal, "interval", 0, "")
	flag.StringVar(&hostName, "host", "", "")
	flag.BoolVar(&showVersion, "v", false, "")
	flag.BoolVar(&showVersion, "version", false, "")
	flag.Parse()

	if showVersion {
		fmt.Printf("ssh-dashboard version %s\n", internal.FullVersion())
		fmt.Printf("  git commit: %s\n", internal.GitCommit)
		fmt.Printf("  build date: %s\n", internal.BuildDate)
		fmt.Printf("  git tag:    %s\n", internal.GitTag)
		os.Exit(0)
	}

	updateInterval := &updateIntervalVal

	interval := 5 * time.Second

	if *updateInterval > 0 {
		if validated := validateInterval(*updateInterval); validated > 0 {
			interval = validated
		}
	} else if envInterval := os.Getenv("SSH_DASHBOARD_INTERVAL"); envInterval != "" {
		if seconds, err := strconv.ParseFloat(envInterval, 64); err == nil {
			if validated := validateInterval(seconds); validated > 0 {
				interval = validated
			}
		}
	}

	hosts, err := internal.ParseSSHConfig("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SSH config: %v\n", err)
		os.Exit(1)
	}

	if len(hosts) == 0 {
		fmt.Fprintf(os.Stderr, "No hosts found in SSH config\n")
		os.Exit(1)
	}

	var initialModel ui.Model

	// If --host is specified, find and connect directly to that host
	if hostName != "" {
		var selectedHost *internal.SSHHost
		for _, host := range hosts {
			if host.Name == hostName {
				selectedHost = &host
				break
			}
		}
		if selectedHost == nil {
			fmt.Fprintf(os.Stderr, "Host '%s' not found in SSH config\n", hostName)
			os.Exit(1)
		}

		initialModel = ui.InitialModelWithHost(*selectedHost, interval)
	} else {
		initialModel = ui.InitialModel(hosts, interval)
	}

	p := tea.NewProgram(initialModel, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running program: %v\n", err)
		os.Exit(1)
	}

	if m, ok := finalModel.(ui.Model); ok {
		if sshHost := m.GetSSHOnExit(); sshHost != "" {
			sshPath, err := exec.LookPath("ssh")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error finding ssh: %v\n", err)
				os.Exit(1)
			}

			args := []string{"ssh", sshHost}
			env := os.Environ()

			err = syscall.Exec(sshPath, args, env)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error executing ssh: %v\n", err)
				os.Exit(1)
			}
		}
	}
}
