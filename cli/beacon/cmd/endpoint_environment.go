package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/environment"
)

var endpointEnvironmentJSON bool

var endpointEnvironmentCmd = &cobra.Command{
	Use:          "environment",
	Short:        "Show how Claude Code and Codex are installed and running on this machine",
	Long:         "Lists every install of the Claude Code and Codex CLIs, the processes they run and what supervises them, the plugins that add MCP servers to them, and the launchd jobs that start them, with warnings for duplicates, broken links, unmanaged or long-running processes, SSH-backed MCP servers and failing jobs. Read-only; command arguments are never retained.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		report := environment.Scan(environment.Options{})
		if endpointEnvironmentJSON {
			return json.NewEncoder(os.Stdout).Encode(report)
		}
		return printEnvironment(cmd.OutOrStdout(), report)
	},
}

func init() {
	endpointEnvironmentCmd.Flags().BoolVar(&endpointEnvironmentJSON, "json", false, "Print the environment report as JSON")
	endpointCmd.AddCommand(endpointEnvironmentCmd)
}

func printEnvironment(out io.Writer, report environment.Report) error {
	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "Host %s, scanned %s\n", report.Host, report.GeneratedAt)
	if !report.Supported {
		fmt.Fprintln(w, "Process and launchd details are collected on macOS only.")
	}
	fmt.Fprintln(w, "\nINSTALLS\nTOOL\tKIND\tSOURCE\tVERSION\tACTIVE\tPATH")
	for _, item := range report.Installs {
		path := item.Path
		if item.Broken {
			path += " -> missing " + item.Target
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", item.Tool, item.Kind, item.Source, item.Version, yesNo(item.Active), path)
	}
	fmt.Fprintln(w, "\nPROCESSES\nPID\tTOOL\tCOMMAND\tUPTIME\tRSS MB\tSUPERVISOR")
	for _, proc := range report.Processes {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s (%s)\n", proc.PID, proc.Tool, strings.TrimSpace(proc.Executable+" "+proc.Subcommand), proc.Uptime, proc.RSSMB, proc.Supervisor, proc.SupervisorKind)
	}
	fmt.Fprintln(w, "\nPLUGINS\nRUNTIME\tPLUGIN\tVERSION\tENABLED\tMCP SERVERS")
	for _, plugin := range report.Plugins {
		servers := make([]string, 0, len(plugin.MCPServers))
		for _, server := range plugin.MCPServers {
			label := server.Name + ":" + server.Transport
			if server.ViaSSH {
				label += "+ssh"
			}
			servers = append(servers, label)
		}
		name := plugin.Name
		if plugin.Marketplace != "" {
			name += "@" + plugin.Marketplace
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", plugin.Runtime, name, plugin.Version, yesNo(plugin.Enabled), strings.Join(servers, ", "))
	}
	fmt.Fprintln(w, "\nLAUNCHD JOBS\nLABEL\tRUNNING\tLAST EXIT\tINTERVAL\tPROGRAM")
	for _, job := range report.LaunchJobs {
		exit := "-"
		if job.LastExit != nil {
			exit = fmt.Sprint(*job.LastExit)
		}
		interval := "-"
		if job.StartInterval > 0 {
			interval = fmt.Sprintf("%ds", job.StartInterval)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", job.Label, yesNo(job.Running), exit, interval, job.Program)
	}
	fmt.Fprintf(w, "\nWARNINGS (%d)\n", len(report.Warnings))
	for _, warning := range report.Warnings {
		fmt.Fprintf(w, "%s\t%s\t%s\n", warning.Kind, warning.Subject, warning.Message)
	}
	return w.Flush()
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "-"
}
