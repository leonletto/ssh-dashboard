package internal

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Screen int

const (
	ScreenHostList Screen = iota
	ScreenConnecting
	ScreenDashboard
	ScreenOverview
	ScreenError
)

type Model struct {
	screen         Screen
	hosts          []SSHHost
	selectedHosts  []SSHHost
	currentHostIdx int
	list           list.Model
	spinner        spinner.Model
	clients        map[string]*SSHClient
	sysInfos       map[string]*SystemInfo
	lastUpdates    map[string]time.Time
	updateInterval time.Duration
	err            error
	width          int
	height         int
	gpuUtilHistory map[string][]float64
	vramHistory    map[string][]float64
	maxHistorySize int
}

type TickMsg time.Time

type SystemInfoMsg struct {
	hostName string
	info     *SystemInfo
	err      error
}

type ConnectedMsg struct {
	hostName string
	client   *SSHClient
	err      error
}

type hostItem struct {
	host     SSHHost
	selected bool
}

func (h hostItem) FilterValue() string { return h.host.Name }
func (h hostItem) Title() string {
	prefix := "  "
	if h.selected {
		prefix = "✓ "
	}
	return prefix + h.host.Name
}
func (h hostItem) Description() string {
	if h.host.Hostname != "" {
		return fmt.Sprintf("  %s@%s:%s", h.host.User, censorHostname(h.host.Hostname), h.host.Port)
	}
	return ""
}

func censorHostname(hostname string) string {
	if hostname == "" {
		return ""
	}

	// for IP addresses (contains dots)
	if strings.Contains(hostname, ".") {
		parts := strings.Split(hostname, ".")
		if len(parts) >= 4 {
			// IPv4: show first octet, censor middle, show last 2 chars of last octet
			lastOctet := parts[len(parts)-1]
			lastPart := lastOctet
			if len(lastOctet) > 2 {
				lastPart = lastOctet[len(lastOctet)-2:]
			}
			return fmt.Sprintf("%s.***.***%s", parts[0], lastPart)
		}
	}

	// for hostnames: show first 3 chars and last 3 chars
	if len(hostname) <= 8 {
		if len(hostname) <= 3 {
			return hostname
		}
		return hostname[:2] + strings.Repeat("*", len(hostname)-2)
	}

	// longer hostname: show first 3 and last 3 with asterisks in between
	return hostname[:3] + strings.Repeat("*", 5) + hostname[len(hostname)-3:]
}

func InitialModel(hosts []SSHHost, updateInterval time.Duration) Model {
	items := make([]list.Item, len(hosts))
	for i, h := range hosts {
		items[i] = hostItem{host: h, selected: false}
	}

	delegate := list.NewDefaultDelegate()
	l := list.New(items, delegate, 0, 0)
	l.Title = "Select SSH Hosts to Monitor (Space to select, Enter to confirm)"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return Model{
		screen:         ScreenHostList,
		hosts:          hosts,
		list:           l,
		spinner:        s,
		clients:        make(map[string]*SSHClient),
		sysInfos:       make(map[string]*SystemInfo),
		lastUpdates:    make(map[string]time.Time),
		updateInterval: updateInterval,
		gpuUtilHistory: make(map[string][]float64),
		vramHistory:    make(map[string][]float64),
		maxHistorySize: 50,
	}
}

func (m *Model) updateListSelection() {
	items := m.list.Items()
	selectedMap := make(map[string]bool)
	for _, h := range m.selectedHosts {
		selectedMap[h.Name] = true
	}

	newItems := make([]list.Item, len(items))
	for i, item := range items {
		if hi, ok := item.(hostItem); ok {
			hi.selected = selectedMap[hi.host.Name]
			newItems[i] = hi
		}
	}
	m.list.SetItems(newItems)
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			for _, client := range m.clients {
				if client != nil {
					client.Close()
				}
			}
			return m, tea.Quit
		case " ":
			if m.screen == ScreenHostList {
				if item, ok := m.list.SelectedItem().(hostItem); ok {
					host := item.host
					found := false
					for i, h := range m.selectedHosts {
						if h.Name == host.Name {
							m.selectedHosts = append(m.selectedHosts[:i], m.selectedHosts[i+1:]...)
							found = true
							break
						}
					}
					if !found {
						m.selectedHosts = append(m.selectedHosts, host)
					}
					m.updateListSelection()
				}
			}
		case "enter":
			if m.screen == ScreenHostList {
				if len(m.selectedHosts) == 0 {
					if item, ok := m.list.SelectedItem().(hostItem); ok {
						m.selectedHosts = append(m.selectedHosts, item.host)
					}
				}
				if len(m.selectedHosts) > 0 {
					hasConnections := len(m.clients) > 0

					if hasConnections {
						m.screen = ScreenDashboard
						cmd := m.connectNewHosts()
						if cmd != nil {
							return m, cmd
						}
					} else {
						m.screen = ScreenConnecting
						return m, m.connectToHosts()
					}
				}
			}
		case "n":
			if m.screen == ScreenDashboard && len(m.selectedHosts) > 1 {
				m.currentHostIdx = (m.currentHostIdx + 1) % len(m.selectedHosts)
				nextHost := m.selectedHosts[m.currentHostIdx]
				if m.clients[nextHost.Name] == nil {
					return m, m.connectToHost(nextHost)
				}
			}
		case "c":
			if m.screen == ScreenDashboard || m.screen == ScreenOverview {
				m.screen = ScreenHostList
				m.updateListSelection()
			}
		case "t":
			if m.screen == ScreenDashboard && len(m.selectedHosts) > 1 {
				m.screen = ScreenOverview
			} else if m.screen == ScreenOverview {
				m.screen = ScreenDashboard
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width, msg.Height-2)

	case ConnectedMsg:
		if msg.err != nil {
			m.err = fmt.Errorf("failed to connect to %s: %w", msg.hostName, msg.err)
			m.screen = ScreenError
			return m, nil
		}
		m.clients[msg.hostName] = msg.client

		if m.screen == ScreenConnecting {
			return m, m.gatherSysInfoForHost(msg.hostName)
		}

		if m.screen == ScreenDashboard || m.screen == ScreenOverview {
			return m, m.gatherSysInfoForHost(msg.hostName)
		}

	case SystemInfoMsg:
		if msg.err != nil {
			return m, nil
		}
		m.sysInfos[msg.hostName] = msg.info
		m.lastUpdates[msg.hostName] = time.Now()

		m.updateGPUHistory()

		if m.screen == ScreenConnecting && len(m.selectedHosts) > 0 {
			firstHost := m.selectedHosts[0]
			if m.clients[firstHost.Name] != nil && m.sysInfos[firstHost.Name] != nil {
				m.screen = ScreenDashboard
				return m, m.tick()
			}
		}

	case TickMsg:
		m.updateGPUHistory()
		return m, tea.Batch(m.gatherAllSysInfo(), m.tick())
	}

	var spinnerCmd tea.Cmd
	m.spinner, spinnerCmd = m.spinner.Update(msg)

	if m.screen == ScreenHostList {
		var listCmd tea.Cmd
		m.list, listCmd = m.list.Update(msg)
		return m, tea.Batch(spinnerCmd, listCmd)
	}

	return m, spinnerCmd
}

func (m Model) View() string {
	switch m.screen {
	case ScreenHostList:
		listView := m.list.View()
		if len(m.selectedHosts) > 0 {
			selectedNames := make([]string, len(m.selectedHosts))
			for i, h := range m.selectedHosts {
				selectedNames[i] = h.Name
			}
			footer := fmt.Sprintf("\nSelected (%d): %s", len(m.selectedHosts), strings.Join(selectedNames, ", "))
			listView += lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render(footer)
		}
		return listView

	case ScreenConnecting:
		return m.renderConnectingProgress()

	case ScreenDashboard:
		if len(m.selectedHosts) > 0 && m.currentHostIdx < len(m.selectedHosts) {
			currentHost := m.selectedHosts[m.currentHostIdx]

			if m.clients[currentHost.Name] == nil || m.sysInfos[currentHost.Name] == nil {
				return m.renderLoading(fmt.Sprintf("Loading %s...", currentHost.Name))
			}

			sysInfo := m.sysInfos[currentHost.Name]
			lastUpdate := m.lastUpdates[currentHost.Name]

			hostIndicator := ""
			if len(m.selectedHosts) > 1 {
				hostIndicator = fmt.Sprintf(" [%d/%d]", m.currentHostIdx+1, len(m.selectedHosts))
			}

			gpuUtilHist := m.gpuUtilHistory[currentHost.Name]
			vramHist := m.vramHistory[currentHost.Name]
			return renderDashboard(currentHost.Name+hostIndicator, sysInfo, m.updateInterval, lastUpdate, m.width, m.height, len(m.selectedHosts) > 1, gpuUtilHist, vramHist)
		}
		return m.renderLoading("Initializing...")

	case ScreenOverview:
		return m.renderOverview()

	case ScreenError:
		return renderError(m.err)
	}

	return ""
}

func (m Model) connectToHosts() tea.Cmd {
	var cmds []tea.Cmd
	for _, host := range m.selectedHosts {
		h := host
		cmds = append(cmds, func() tea.Msg {
			client, err := NewSSHClient(h)
			return ConnectedMsg{hostName: h.Name, client: client, err: err}
		})
	}
	if len(cmds) > 0 {
		return tea.Batch(cmds...)
	}
	return nil
}

func (m Model) connectToHost(host SSHHost) tea.Cmd {
	return func() tea.Msg {
		client, err := NewSSHClient(host)
		return ConnectedMsg{hostName: host.Name, client: client, err: err}
	}
}

func (m Model) connectNewHosts() tea.Cmd {
	var cmds []tea.Cmd
	for _, host := range m.selectedHosts {
		// Only connect if not already connected
		if m.clients[host.Name] == nil {
			h := host
			cmds = append(cmds, func() tea.Msg {
				client, err := NewSSHClient(h)
				return ConnectedMsg{hostName: h.Name, client: client, err: err}
			})
		}
	}
	if len(cmds) > 0 {
		return tea.Batch(cmds...)
	}
	return nil
}

func (m Model) gatherAllSysInfo() tea.Cmd {
	var cmds []tea.Cmd
	for _, host := range m.selectedHosts {
		h := host
		client := m.clients[h.Name]
		if client != nil {
			cmds = append(cmds, func() tea.Msg {
				info, err := GatherSystemInfo(client)
				return SystemInfoMsg{hostName: h.Name, info: info, err: err}
			})
		}
	}
	return tea.Batch(cmds...)
}

func (m Model) gatherSysInfoForHost(hostName string) tea.Cmd {
	client := m.clients[hostName]
	if client == nil {
		return nil
	}
	return func() tea.Msg {
		info, err := GatherSystemInfo(client)
		return SystemInfoMsg{hostName: hostName, info: info, err: err}
	}
}

func (m Model) tick() tea.Cmd {
	return tea.Tick(m.updateInterval, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m *Model) updateGPUHistory() {
	for _, host := range m.selectedHosts {
		sysInfo := m.sysInfos[host.Name]
		if sysInfo == nil || len(sysInfo.GPUs) == 0 {
			continue
		}

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
		avgUtil := float64(totalUtil) / float64(len(sysInfo.GPUs))

		if m.vramHistory[host.Name] == nil {
			m.vramHistory[host.Name] = make([]float64, 0)
		}
		if m.gpuUtilHistory[host.Name] == nil {
			m.gpuUtilHistory[host.Name] = make([]float64, 0)
		}

		m.vramHistory[host.Name] = append(m.vramHistory[host.Name], vramPercent)
		m.gpuUtilHistory[host.Name] = append(m.gpuUtilHistory[host.Name], avgUtil)

		if len(m.vramHistory[host.Name]) > m.maxHistorySize {
			m.vramHistory[host.Name] = m.vramHistory[host.Name][1:]
		}
		if len(m.gpuUtilHistory[host.Name]) > m.maxHistorySize {
			m.gpuUtilHistory[host.Name] = m.gpuUtilHistory[host.Name][1:]
		}
	}
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86")).
			Background(lipgloss.Color("63")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("63"))

	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("196")).
			Padding(1, 2)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2)
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

func renderSparkline(data []float64, width int, color lipgloss.Color) string {
	if len(data) == 0 {
		return strings.Repeat(" ", width)
	}

	sparkChars := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	minVal := 0.0
	maxVal := 100.0
	valRange := maxVal - minVal

	pointsPerChar := float64(len(data)) / float64(width)
	if pointsPerChar < 1 {
		pointsPerChar = 1
	}

	var result strings.Builder
	style := lipgloss.NewStyle().Foreground(color)

	for i := 0; i < width; i++ {
		startIdx := int(float64(i) * pointsPerChar)
		endIdx := int(float64(i+1) * pointsPerChar)
		if endIdx > len(data) {
			endIdx = len(data)
		}
		if startIdx >= len(data) {
			result.WriteString(" ")
			continue
		}

		sum := 0.0
		count := 0
		for j := startIdx; j < endIdx; j++ {
			sum += data[j]
			count++
		}
		avg := sum / float64(count)

		normalized := (avg - minVal) / valRange
		if normalized > 1 {
			normalized = 1
		}
		if normalized < 0 {
			normalized = 0
		}

		charIdx := int(normalized * float64(len(sparkChars)-1))
		if charIdx >= len(sparkChars) {
			charIdx = len(sparkChars) - 1
		}
		if charIdx < 0 {
			charIdx = 0
		}

		result.WriteRune(sparkChars[charIdx])
	}

	return style.Render(result.String())
}

func (m Model) renderLoading(message string) string {
	return boxStyle.Render(fmt.Sprintf("%s %s", m.spinner.View(), message))
}

func (m Model) renderConnectingProgress() string {
	var b strings.Builder

	title := "  System Dashboard - Connecting  "
	connectedCount := len(m.clients)
	totalCount := len(m.selectedHosts)
	subtitle := fmt.Sprintf("Connecting to %d host(s) in parallel... (%d/%d ready)", totalCount, connectedCount, totalCount)

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

func renderError(err error) string {
	return errorStyle.Render(fmt.Sprintf("Error: %v\n\nPress 'q' to quit", err))
}

func (m Model) renderOverview() string {
	var b strings.Builder

	title := fmt.Sprintf("  Overview - All Hosts (%d)  ", len(m.selectedHosts))
	subtitle := fmt.Sprintf("Last Updated: %s | Interval: %.0fs | 't' per-host | 'c' add hosts | 'q' quit",
		time.Now().Format("15:04:05"), m.updateInterval.Seconds())

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

func (m Model) renderSingleHostOverview(host SSHHost) string {
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

func renderDashboard(hostName string, info *SystemInfo, updateInterval time.Duration, lastUpdate time.Time, width, height int, multiHost bool, gpuUtilHistory, vramHistory []float64) string {
	var b strings.Builder

	title := fmt.Sprintf("  System Dashboard - %s  ", hostName)
	navHint := ""
	if multiHost {
		navHint = " | 'n' next | 't' overview"
	}
	subtitle := fmt.Sprintf("Last Updated: %s | Interval: %.0fs%s | 'c' add hosts | 'q' quit",
		lastUpdate.Format("15:04:05"), updateInterval.Seconds(), navHint)

	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(subtitle))
	b.WriteString("\n\n")

	b.WriteString(renderCPUSection(info.CPU))
	b.WriteString("\n")

	b.WriteString(renderRAMAndDiskSection(info.RAM, info.Disk))

	if len(info.GPUs) > 1 {
		b.WriteString("\n")
		b.WriteString(renderAggregateGPUSection(info.GPUs, gpuUtilHistory, vramHistory))
	}

	if len(info.GPUs) > 0 {
		b.WriteString("\n")
		b.WriteString(renderGPUSection(info.GPUs))
	}

	return b.String()
}

func renderCPUSection(cpu CPUInfo) string {
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

func renderAggregateGPUSection(gpus []GPUInfo, gpuUtilHistory, vramHistory []float64) string {
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

	const barWidth = 50
	const graphWidth = 50

	// VRAM section
	vramLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render("VRAM")
	var vramLeft strings.Builder
	vramLeft.WriteString(fmt.Sprintf("%s %.1f/%.1f GB (%.1f%%) across %d GPUs\n", vramLabel, usedVRAMGB, totalVRAMGB, vramPercent, len(gpus)))
	vramBar := renderProgressBar(vramPercent, barWidth, lipgloss.Color("39"))
	vramLeft.WriteString(vramBar)

	var vramRight strings.Builder
	if len(vramHistory) > 0 {
		vramRight.WriteString("History\n")
		vramRight.WriteString(renderSparkline(vramHistory, graphWidth, lipgloss.Color("39")))
	} else {
		vramRight.WriteString("\n")
	}

	vramRow := lipgloss.JoinHorizontal(lipgloss.Top, vramLeft.String(), "        ", vramRight.String())
	b.WriteString("  ")
	b.WriteString(vramRow)
	b.WriteString("\n\n")

	// Util section
	utilLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("Util")
	var utilLeft strings.Builder
	utilLeft.WriteString(fmt.Sprintf("%s %.1f%% average\n", utilLabel, avgUtil))
	utilBar := renderProgressBar(avgUtil, barWidth, lipgloss.Color("208"))
	utilLeft.WriteString(utilBar)

	var utilRight strings.Builder
	if len(gpuUtilHistory) > 0 {
		utilRight.WriteString("History\n")
		utilRight.WriteString(renderSparkline(gpuUtilHistory, graphWidth, lipgloss.Color("208")))
	} else {
		utilRight.WriteString("\n")
	}

	utilRow := lipgloss.JoinHorizontal(lipgloss.Top, utilLeft.String(), "        ", utilRight.String())
	b.WriteString("  ")
	b.WriteString(utilRow)
	b.WriteString("\n")

	return b.String()
}

func renderGPUSection(gpus []GPUInfo) string {
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

func renderSingleGPU(gpu GPUInfo) string {
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

func renderRAMAndDiskSection(ram RAMInfo, disks []DiskInfo) string {
	ramSection := renderRAMSection(ram)
	diskSection := renderDiskSection(disks)

	return lipgloss.JoinHorizontal(lipgloss.Top, diskSection, "    ", ramSection) + "\n"
}

func renderRAMSection(ram RAMInfo) string {
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

func renderDiskSection(disks []DiskInfo) string {
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
