# SSH Host Key Verification Prompt Implementation Plan

## Problem Statement

The SSH Dashboard currently fails when connecting to hosts with unknown host keys, requiring users to manually run `ssh hostname` to accept the host key first. This creates a poor user experience and breaks the seamless workflow.

**Current Error Flow:**
1. SSH Dashboard attempts connection
2. Host key not in `known_hosts` 
3. Connection fails with error: "host key verification failed: hostname is not in known_hosts"
4. User must exit dashboard and run `ssh hostname` manually
5. User must restart SSH Dashboard

## Root Cause Analysis

The issue is in `internal/ssh.go` lines 215-226 in the `getHostKeyCallback()` function:

```go
return ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
    err := hostKeyCallback(hostname, remote, key)
    if err != nil {
        if keyErr, ok := err.(*knownhosts.KeyError); ok && len(keyErr.Want) == 0 {
            return fmt.Errorf("host key verification failed: %s is not in known_hosts. Add the host key to %s or run 'ssh %s' first to accept the host key", hostname, knownHostsPath, hostname)
        }
        // ... other error handling
    }
    return nil
})
```

Instead of prompting the user interactively, it immediately returns an error.

## Comprehensive Solution Plan

### Phase 1: Create New Message Types and UI States

#### 1.1 Add New Message Types (`internal/ui/model.go`)

```go
type HostKeyPromptMsg struct {
    hostName    string
    hostname    string
    fingerprint string
    keyType     string
    remoteAddr  string
}

type HostKeyResponseMsg struct {
    hostName string
    accepted bool
}
```

#### 1.2 Add New Screen State

```go
const (
    ScreenHostList Screen = iota
    ScreenConnecting
    ScreenDashboard
    ScreenOverview
    ScreenHostKeyPrompt  // New state
)
```

#### 1.3 Extend Model Struct

```go
type Model struct {
    // ... existing fields ...
    pendingHostKey       *HostKeyPromptMsg
    hostKeyPromptVisible bool
    hostKeyChannels      map[string]chan bool // For async communication
}
```

### Phase 2: Modify SSH Connection Logic

#### 2.1 Create Interactive Host Key Callback (`internal/ssh.go`)

```go
type HostKeyPromptInfo struct {
    HostName    string
    Hostname    string
    RemoteAddr  string
    Key         ssh.PublicKey
    Fingerprint string
    KeyType     string
}

func getInteractiveHostKeyCallback(promptChan chan<- HostKeyPromptInfo, responseChan <-chan bool) (ssh.HostKeyCallback, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return nil, fmt.Errorf("unable to get user home directory: %w", err)
    }

    knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
    
    // Create known_hosts if it doesn't exist
    if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
        if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); err != nil {
            return nil, fmt.Errorf("unable to create .ssh directory: %w", err)
        }
        if _, err := os.Create(knownHostsPath); err != nil {
            return nil, fmt.Errorf("unable to create known_hosts file: %w", err)
        }
    }

    hostKeyCallback, err := knownhosts.New(knownHostsPath)
    if err != nil {
        return nil, fmt.Errorf("unable to load known_hosts: %w", err)
    }

    return ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
        err := hostKeyCallback(hostname, remote, key)
        if err != nil {
            if keyErr, ok := err.(*knownhosts.KeyError); ok && len(keyErr.Want) > 0 {
                // Host key has changed - this is a security issue, don't prompt
                return fmt.Errorf("host key verification failed: host key has changed for %s. Remove the old key from %s if you trust this connection", hostname, knownHostsPath)
            } else if keyErr, ok := err.(*knownhosts.KeyError); ok && len(keyErr.Want) == 0 {
                // Unknown host key - prompt user
                promptInfo := HostKeyPromptInfo{
                    HostName:    hostname,
                    Hostname:    hostname,
                    RemoteAddr:  remote.String(),
                    Key:         key,
                    Fingerprint: formatHostKeyFingerprint(key),
                    KeyType:     key.Type(),
                }
                
                // Send prompt to UI
                promptChan <- promptInfo
                
                // Wait for user response
                accepted := <-responseChan
                
                if accepted {
                    // Add to known_hosts
                    if err := addHostKeyToKnownHosts(hostname, key); err != nil {
                        return fmt.Errorf("failed to add host key to known_hosts: %w", err)
                    }
                    return nil
                } else {
                    return fmt.Errorf("host key verification failed: user rejected host key for %s", hostname)
                }
            }
            return fmt.Errorf("host key verification failed: %w", err)
        }
        return nil
    }), nil
}
```

#### 2.2 Add Host Key Utilities

```go
func formatHostKeyFingerprint(key ssh.PublicKey) string {
    hash := sha256.Sum256(key.Marshal())
    return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}

func addHostKeyToKnownHosts(hostname string, key ssh.PublicKey) error {
    home, err := os.UserHomeDir()
    if err != nil {
        return err
    }
    
    knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
    
    file, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil {
        return err
    }
    defer file.Close()
    
    line := fmt.Sprintf("%s %s %s\n", hostname, key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
    _, err = file.WriteString(line)
    return err
}
```

#### 2.3 Modify NewSSHClient for Interactive Mode

```go
func NewSSHClientInteractive(host SSHHost, promptChan chan<- HostKeyPromptInfo, responseChan <-chan bool) (*SSHClient, error) {
    // ... existing auth setup code ...
    
    hostKeyCallback, err := getInteractiveHostKeyCallback(promptChan, responseChan)
    if err != nil {
        return nil, fmt.Errorf("failed to setup host key verification: %w", err)
    }
    
    config := &ssh.ClientConfig{
        User:            host.User,
        Auth:            authMethods,
        HostKeyCallback: hostKeyCallback,
        Timeout:         10 * time.Second,
    }
    
    // ... rest of connection logic ...
}
```

### Phase 3: Update UI Flow

#### 3.1 Modify Connection Logic (`internal/ui/connect.go`)

```go
func (m Model) connectToHostsInteractive() tea.Cmd {
    var cmds []tea.Cmd
    for _, host := range m.selectedHosts {
        h := host
        cmds = append(cmds, func() tea.Msg {
            promptChan := make(chan HostKeyPromptInfo, 1)
            responseChan := make(chan bool, 1)
            
            // Store channels for this host
            m.hostKeyChannels[h.Name] = responseChan
            
            go func() {
                // Listen for host key prompts
                select {
                case promptInfo := <-promptChan:
                    // Send prompt to UI
                    return HostKeyPromptMsg{
                        hostName:    h.Name,
                        hostname:    promptInfo.Hostname,
                        fingerprint: promptInfo.Fingerprint,
                        keyType:     promptInfo.KeyType,
                    }
                }
            }()
            
            client, err := internal.NewSSHClientInteractive(h, promptChan, responseChan)
            return ConnectedMsg{hostName: h.Name, client: client, err: err}
        })
    }
    if len(cmds) > 0 {
        return tea.Batch(cmds...)
    }
    return nil
}
```

#### 3.2 Add Host Key Prompt Rendering (`internal/ui/render.go`)

```go
func (m Model) renderHostKeyPrompt() string {
    if m.pendingHostKey == nil {
        return "Error: No pending host key prompt"
    }
    
    var b strings.Builder
    
    // Title
    title := "  SSH Host Key Verification  "
    b.WriteString(titleStyle.Render(title))
    b.WriteString("\n\n")
    
    // Warning
    warning := "⚠️  WARNING: Unknown Host Key"
    b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true).Render(warning))
    b.WriteString("\n\n")
    
    // Host info
    b.WriteString(fmt.Sprintf("Host: %s\n", m.pendingHostKey.hostname))
    b.WriteString(fmt.Sprintf("Key Type: %s\n", m.pendingHostKey.keyType))
    b.WriteString(fmt.Sprintf("Fingerprint: %s\n\n", m.pendingHostKey.fingerprint))
    
    // Security message
    securityMsg := "The authenticity of this host cannot be established.\n" +
                  "This could be a man-in-the-middle attack.\n" +
                  "Only continue if you trust this connection.\n\n"
    b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(securityMsg))
    
    // Options
    b.WriteString("Do you want to continue connecting and add this host to known hosts?\n\n")
    b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("y/yes") + " - Accept and continue\n")
    b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("n/no") + "  - Reject and cancel\n")
    
    return b.String()
}
```

#### 3.3 Handle User Input (`internal/ui/update.go`)

```go
case HostKeyPromptMsg:
    m.screen = ScreenHostKeyPrompt
    m.pendingHostKey = &msg
    return m, nil

case tea.KeyMsg:
    if m.screen == ScreenHostKeyPrompt && m.pendingHostKey != nil {
        switch strings.ToLower(msg.String()) {
        case "y", "yes":
            // Accept host key
            if responseChan, exists := m.hostKeyChannels[m.pendingHostKey.hostName]; exists {
                responseChan <- true
                delete(m.hostKeyChannels, m.pendingHostKey.hostName)
            }
            m.screen = ScreenConnecting
            m.pendingHostKey = nil
            return m, nil
            
        case "n", "no":
            // Reject host key
            if responseChan, exists := m.hostKeyChannels[m.pendingHostKey.hostName]; exists {
                responseChan <- false
                delete(m.hostKeyChannels, m.pendingHostKey.hostName)
            }
            m.screen = ScreenHostList
            m.pendingHostKey = nil
            return m, nil
        }
    }
```

#### 3.4 Update View Switch (`internal/ui/view.go`)

```go
func (m Model) View() string {
    switch m.screen {
    case ScreenHostList:
        // ... existing code ...
    case ScreenConnecting:
        // ... existing code ...
    case ScreenDashboard:
        // ... existing code ...
    case ScreenOverview:
        // ... existing code ...
    case ScreenHostKeyPrompt:
        return m.renderHostKeyPrompt()
    }
    return ""
}
```

### Phase 4: Implementation Priority

#### High Priority (Core Functionality)
1. Interactive host key callback
2. Basic prompt UI
3. Accept/reject handling  
4. Add to known_hosts functionality

#### Medium Priority (User Experience)
1. Proper fingerprint formatting
2. Security warnings
3. Retry after acceptance
4. Better error messages

#### Low Priority (Polish)
1. Advanced key management
2. Configuration options
3. Detailed logging
4. Host key caching

### Alternative Simpler Approach

For a quicker implementation, add a command-line flag:

```go
// Add to main.go
var acceptNewHostKeys bool
flag.BoolVar(&acceptNewHostKeys, "accept-new-hostkeys", false, "Automatically accept new host keys")

// Modify getHostKeyCallback() to auto-accept when flag is set
if acceptNewHostKeys && keyErr, ok := err.(*knownhosts.KeyError); ok && len(keyErr.Want) == 0 {
    if err := addHostKeyToKnownHosts(hostname, key); err != nil {
        return fmt.Errorf("failed to add host key: %w", err)
    }
    return nil
}
```

This provides immediate functionality while the full interactive solution is developed.

## Benefits

1. **User-Friendly**: No need to exit and run `ssh hostname` manually
2. **Secure**: Still shows fingerprint for verification  
3. **Consistent**: Matches standard SSH behavior
4. **Non-Breaking**: Existing functionality remains unchanged
5. **Extensible**: Can be enhanced with additional security features

## Security Considerations

- Always show host key fingerprint for verification
- Distinguish between unknown keys (prompt) and changed keys (security warning)
- Store accepted keys in standard `known_hosts` format
- Provide clear security warnings about potential MITM attacks
