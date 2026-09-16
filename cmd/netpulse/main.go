package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Expanded map of common services
var serviceMap = map[int]string{
	21:   "FTP (File Transfer - Old school file sharing)",
	22:   "SSH (Secure Shell - Remote command line access)",
	25:   "SMTP (Email routing)",
	53:   "DNS (Internet Phonebook - Turns names into IPs)",
	80:   "HTTP (Standard Web - Unencrypted)",
	443:  "HTTPS (Secure Web - Encrypted)",
	3306: "MySQL (Database - Where app data is stored)",
	5432: "PostgreSQL (Database - Another common app DB)",
	8080: "HTTP-Alt (Common for web development testing)",
}

func scanPort(ip string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	// Fast timeout so we don't wait forever on closed doors
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return
	}
	conn.Close()

	serviceName, exists := serviceMap[port]
	if !exists {
		serviceName = "Unknown Custom Service"
	}

	fmt.Printf("[FOUND] %-25s | Port: %-5d | Target: %s\n", serviceName, port, ip)
}

func main() {
	target := "8.8.8.8"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	fmt.Printf("Service Discovery Scan initiated for: %s\n", target)
	fmt.Println("------------------------------------------------------------")

	var wg sync.WaitGroup
	for port := range serviceMap {
		wg.Add(1)
		go scanPort(target, port, &wg)
	}

	wg.Wait()
	fmt.Println("------------------------------------------------------------")
	fmt.Println("Scan Complete.")
}
