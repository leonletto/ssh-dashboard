package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alpindale/ssh-dashboard/internal"
	"github.com/charmbracelet/lipgloss"
)

func renderProgressBar(percent float64, width int, color lipgloss.Color) string {
	if percent > 100 {
		percent = 100
	}
	if percent < 0 {
		percent = 0
	}

	filled := int(float64(width) * percent / 100.0)
	empty := width - filled

	filledStyle := lipgloss.NewStyle().Foreground(color)
	emptyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	bar := filledStyle.Render(strings.Repeat("█", filled)) +
		emptyStyle.Render(strings.Repeat("░", empty))

	return bar
}

func (m Model) renderConnectingProgress() string {
	var b strings.Builder

	title := "  System Dashboard - Connecting  "
	connectedCount := len(m.clients)
	totalCount := len(m.selectedHosts)
	subtitle := fmt.Sprintf("v%s | Connecting to %d host(s)... (%d/%d ready)", internal.ShortVersion(), totalCount, connectedCount, totalCount)

	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(subtitle))
	b.WriteString("\n\n")

	maxNameLen := 0
	for _, host := range m.selectedHosts {
		if len(host.Name) > maxNameLen {
			maxNameLen = len(host.Name)
		}
	}

	for _, host := range m.selectedHosts {
		client := m.clients[host.Name]
		sysInfo := m.sysInfos[host.Name]

		statusIcon := m.spinner.View()
		statusText := "Connecting..."
		statusColor := lipgloss.Color("240")

		if client != nil {
			if sysInfo != nil {
				statusIcon = "✓"
				statusText = "Ready"
				statusColor = lipgloss.Color("10")
			} else {
				statusIcon = m.spinner.View()
				statusText = "Gathering information..."
				statusColor = lipgloss.Color("11")
			}
		}

		paddedName := host.Name + strings.Repeat(" ", maxNameLen-len(host.Name))
		hostName := headerStyle.Render("● " + paddedName)
		status := lipgloss.NewStyle().Foreground(statusColor).Render(fmt.Sprintf("%s %s", statusIcon, statusText))

		b.WriteString(fmt.Sprintf("  %s  %s\n", hostName, status))
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("Please wait..."))

	return b.String()
}

func (m Model) renderOverview() string {
	var b strings.Builder

	title := fmt.Sprintf("  Overview - All Hosts (%d)  ", len(m.selectedHosts))
	subtitle := fmt.Sprintf("v%s | Last Updated: %s | Interval: %s | 't' per-host | 'c' add hosts | 'q' quit",
		internal.ShortVersion(), time.Now().Format("15:04:05"), formatInterval(m.updateInterval))

	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(subtitle))
	b.WriteString("\n\n")

	for i := 0; i < len(m.selectedHosts); i += 2 {
		var leftHost, rightHost string

		leftHost = m.renderSingleHostOverview(m.selectedHosts[i])

		if i+1 < len(m.selectedHosts) {
			rightHost = m.renderSingleHostOverview(m.selectedHosts[i+1])
			row := lipgloss.JoinHorizontal(lipgloss.Top, leftHost, "    ", rightHost)
			b.WriteString(row)
		} else {
			b.WriteString(leftHost)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderSingleHostOverview(host internal.SSHHost) string {
	var b strings.Builder

	sysInfo := m.sysInfos[host.Name]

	if sysInfo == nil {
		b.WriteString(headerStyle.Render(fmt.Sprintf("● %s", host.Name)))
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("Loading..."))
		b.WriteString("\n")
		return b.String()
	}

	b.WriteString(headerStyle.Render(fmt.Sprintf("● %s", host.Name)))
	b.WriteString("\n")

	cpuUsage := sysInfo.CPU.Usage
	if cpuUsage == "" {
		cpuUsage = "N/A"
	}
	b.WriteString(fmt.Sprintf("  CPU: %s", cpuUsage))
	b.WriteString("\n")

	if sysInfo.RAM.Total > 0 {
		b.WriteString(fmt.Sprintf("  RAM: %.1f / %.1f GB (%.0f%%)",
			float64(sysInfo.RAM.Used)/1024,
			float64(sysInfo.RAM.Total)/1024,
			sysInfo.RAM.UsagePercent))
	} else {
		b.WriteString("  RAM: N/A")
	}
	b.WriteString("\n")

	if len(sysInfo.Disk) > 0 {
		disk := sysInfo.Disk[0]
		b.WriteString(fmt.Sprintf("  Disk: %s / %s (%s)", disk.Used, disk.Size, disk.UsagePercent))
	} else {
		b.WriteString("  Disk: N/A")
	}
	b.WriteString("\n")

	if len(sysInfo.GPUs) > 0 {
		var totalVRAM, usedVRAM int
		var totalUtil int
		for _, gpu := range sysInfo.GPUs {
			totalVRAM += gpu.VRAMTotal
			usedVRAM += gpu.VRAMUsed
			totalUtil += gpu.Utilization
		}

		vramPercent := 0.0
		if totalVRAM > 0 {
			vramPercent = (float64(usedVRAM) / float64(totalVRAM)) * 100
		}

		avgUtil := 0
		if len(sysInfo.GPUs) > 0 {
			avgUtil = totalUtil / len(sysInfo.GPUs)
		}

		barWidth := 50
		vramBar := renderProgressBar(vramPercent, barWidth, lipgloss.Color("33"))
		utilBar := renderProgressBar(float64(avgUtil), barWidth, lipgloss.Color("208"))

		b.WriteString(fmt.Sprintf("  GPU VRAM: %.1f / %.1f GB (%.0f%%)\n", float64(usedVRAM)/1024, float64(totalVRAM)/1024, vramPercent))
		b.WriteString("  " + vramBar + "\n")
		b.WriteString(fmt.Sprintf("  GPU Util: %d%% avg\n", avgUtil))
		b.WriteString("  " + utilBar + "\n")
	} else {
		paddingLine := strings.Repeat(" ", 52)
		b.WriteString("  GPU: N/A\n")
		b.WriteString(paddingLine + "\n")
		b.WriteString(paddingLine + "\n")
		b.WriteString(paddingLine + "\n")
	}

	return b.String()
}

func renderDashboard(hostName string, info *internal.SystemInfo, updateInterval time.Duration, lastUpdate time.Time, width, height int, multiHost bool) string {
	var b strings.Builder

	title := fmt.Sprintf("  System Dashboard - %s  ", hostName)
	navHint := ""
	if multiHost {
		navHint = " | 'n' next | 't' overview"
	}
	subtitle := fmt.Sprintf("v%s | Last Updated: %s | Interval: %s%s | 's' shell | 'c' add hosts | 'q' quit",
		internal.ShortVersion(), lastUpdate.Format("15:04:05"), formatInterval(updateInterval), navHint)

	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(subtitle))
	b.WriteString("\n\n")

	b.WriteString(renderCPUSection(info.CPU))
	b.WriteString("\n")

	b.WriteString(renderRAMAndDiskSection(info.RAM, info.Disk))

	if len(info.GPUs) > 1 {
		b.WriteString("\n")
		b.WriteString(renderAggregateGPUSection(info.GPUs))
	}

	if len(info.GPUs) > 0 {
		b.WriteString("\n")
		b.WriteString(renderGPUSection(info.GPUs))
	}

	return b.String()
}

func renderCPUSection(cpu internal.CPUInfo) string {
	var parts []string

	if cpu.Model != "" {
		parts = append(parts, cpu.Model)
	}
	if cpu.Count != "" {
		parts = append(parts, fmt.Sprintf("%s cores", cpu.Count))
	}
	parts = append(parts, fmt.Sprintf("Usage: %s", cpu.Usage))

	cpuInfo := strings.Join(parts, "  |  ")
	return headerStyle.Render("● CPU") + "  " + cpuInfo + "\n"
}

func renderAggregateGPUSection(gpus []internal.GPUInfo) string {
	var b strings.Builder

	var totalVRAM, usedVRAM int
	var totalUtil int
	for _, gpu := range gpus {
		totalVRAM += gpu.VRAMTotal
		usedVRAM += gpu.VRAMUsed
		totalUtil += gpu.Utilization
	}

	vramPercent := 0.0
	if totalVRAM > 0 {
		vramPercent = (float64(usedVRAM) / float64(totalVRAM)) * 100
	}
	avgUtil := 0.0
	if len(gpus) > 0 {
		avgUtil = float64(totalUtil) / float64(len(gpus))
	}

	totalVRAMGB := float64(totalVRAM) / 1024.0
	usedVRAMGB := float64(usedVRAM) / 1024.0

	b.WriteString(headerStyle.Render("● Total GPU Pressure"))
	b.WriteString("\n\n")

	const fullBarWidth = 106

	vramLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render("VRAM")
	b.WriteString(fmt.Sprintf("  %s %.1f/%.1f GB (%.1f%%) across %d GPUs\n", vramLabel, usedVRAMGB, totalVRAMGB, vramPercent, len(gpus)))
	b.WriteString("  ")
	b.WriteString(renderProgressBar(vramPercent, fullBarWidth, lipgloss.Color("39")))
	b.WriteString("\n")

	utilLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("Util")
	b.WriteString(fmt.Sprintf("  %s %.1f%% average\n", utilLabel, avgUtil))
	b.WriteString("  ")
	b.WriteString(renderProgressBar(avgUtil, fullBarWidth, lipgloss.Color("208")))
	b.WriteString("\n")

	return b.String()
}

func renderGPUSection(gpus []internal.GPUInfo) string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("● GPU Information"))
	b.WriteString("\n\n")

	for i := 0; i < len(gpus); i += 2 {
		var leftGPU, rightGPU string

		leftGPU = renderSingleGPU(gpus[i])

		if i+1 < len(gpus) {
			rightGPU = renderSingleGPU(gpus[i+1])
			row := lipgloss.JoinHorizontal(lipgloss.Top, leftGPU, "    ", rightGPU)
			b.WriteString(row)
		} else {
			b.WriteString(leftGPU)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func renderSingleGPU(gpu internal.GPUInfo) string {
	var b strings.Builder

	vramTotalGB := float64(gpu.VRAMTotal) / 1024.0
	vramUsedGB := float64(gpu.VRAMUsed) / 1024.0
	vramPercent := 0.0
	if gpu.VRAMTotal > 0 {
		vramPercent = (float64(gpu.VRAMUsed) / float64(gpu.VRAMTotal)) * 100
	}

	gpuIndex := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		Render(gpu.Index)

	gpuName := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render(gpu.Name)

	powerPercent := 0.0
	if gpu.PowerLimit > 0 {
		powerPercent = (float64(gpu.PowerDraw) / float64(gpu.PowerLimit)) * 100
	}
	var powerColor lipgloss.Color
	if powerPercent < 70 {
		powerColor = lipgloss.Color("10") // Green
	} else if powerPercent < 90 {
		powerColor = lipgloss.Color("11") // Yellow
	} else {
		powerColor = lipgloss.Color("196") // Red
	}
	powerText := lipgloss.NewStyle().
		Foreground(powerColor).
		Render(fmt.Sprintf("%dW", gpu.PowerDraw))

	var tempColor lipgloss.Color
	if gpu.Temperature < 70 {
		tempColor = lipgloss.Color("10") // Green
	} else if gpu.Temperature < 80 {
		tempColor = lipgloss.Color("11") // Yellow
	} else if gpu.Temperature < 85 {
		tempColor = lipgloss.Color("208") // Orange
	} else {
		tempColor = lipgloss.Color("196") // Red
	}
	tempText := lipgloss.NewStyle().
		Foreground(tempColor).
		Render(fmt.Sprintf("%d°C", gpu.Temperature))

	const barWidth = 50

	b.WriteString(fmt.Sprintf("  %s  %s  %s  %s\n", gpuIndex, gpuName, powerText, tempText))

	vramLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render("VRAM")
	b.WriteString(fmt.Sprintf("  %s %.1f/%.1f GB (%.1f%%)\n", vramLabel, vramUsedGB, vramTotalGB, vramPercent))
	b.WriteString("  ")
	b.WriteString(renderProgressBar(vramPercent, barWidth, lipgloss.Color("39")))
	b.WriteString("\n")

	utilLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("Util")
	b.WriteString(fmt.Sprintf("  %s %d%%\n", utilLabel, gpu.Utilization))
	b.WriteString("  ")
	b.WriteString(renderProgressBar(float64(gpu.Utilization), barWidth, lipgloss.Color("208")))
	b.WriteString("\n")

	return b.String()
}

func renderRAMAndDiskSection(ram internal.RAMInfo, disks []internal.DiskInfo) string {
	ramSection := renderRAMSection(ram)
	diskSection := renderDiskSection(disks)

	return lipgloss.JoinHorizontal(lipgloss.Top, diskSection, "    ", ramSection) + "\n"
}

func renderRAMSection(ram internal.RAMInfo) string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("● RAM Information"))
	b.WriteString("\n")

	totalGB := float64(ram.Total) / 1024.0
	usedGB := float64(ram.Used) / 1024.0

	b.WriteString(fmt.Sprintf("  %.1f GB / %.1f GB (%.1f%%)\n", usedGB, totalGB, ram.UsagePercent))
	b.WriteString("  ")
	b.WriteString(renderProgressBar(ram.UsagePercent, 50, lipgloss.Color("10")))
	b.WriteString("\n")

	return b.String()
}

func renderDiskSection(disks []internal.DiskInfo) string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("● Disk Usage"))
	b.WriteString("\n")

	for _, disk := range disks {
		usageStr := strings.TrimSuffix(disk.UsagePercent, "%")
		usagePercent := 0.0
		if val, err := strconv.ParseFloat(usageStr, 64); err == nil {
			usagePercent = val
		}

		b.WriteString(fmt.Sprintf("  %s  %s  %s / %s (%s)\n",
			disk.Device, disk.MountPoint, disk.Used, disk.Size, disk.UsagePercent))

		b.WriteString("  ")

		var barColor lipgloss.Color
		if usagePercent >= 90 {
			barColor = lipgloss.Color("196") // Red
		} else if usagePercent >= 75 {
			barColor = lipgloss.Color("208") // Orange
		} else {
			barColor = lipgloss.Color("10") // Green
		}

		b.WriteString(renderProgressBar(usagePercent, 50, barColor))
		b.WriteString("\n\n")
	}

	return b.String()
}
