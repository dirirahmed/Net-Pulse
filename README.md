Net-Pulse: Concurrent Service Auditor
🚀 The "Point" of this Project
Net-Pulse is a high-performance network diagnostic tool built in Go. While a standard "ping" only tells you if a computer is on, Net-Pulse tells you if the services on that computer (like Web Servers or Databases) are actually functioning and ready to talk.

This project demonstrates a deep understanding of the TCP/IP stack and concurrency patterns.

🛠️ What it actually does
Service Discovery: It maps common port numbers (443, 53, 3306) to their real-world functions (HTTPS, DNS, MySQL) so you can see what a server is "selling".

TCP Handshake Validation: Instead of guessing, it completes a full SYN/ACK handshake with the target to ensure the connection is stable.

Parallel Probing: Using Goroutines, it knocks on every "door" (port) at the exact same time, making it significantly faster than sequential scanners.

💻 Usage
    Bash
    go run main.go <target-ip-or-domain>
    Example: go run main.go 8.8.8.8 This will identify if Google's Public DNS and Web services are active.