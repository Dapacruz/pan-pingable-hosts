// Package pan-pingable-hosts harvests pingable IP addresses from a firewall's ARP cache
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-ping/ping"
	"golang.org/x/term"
)

var wg sync.WaitGroup

type ArpCache struct {
	Entries []Interface `xml:"result>entries>entry"`
}

type Interface struct {
	Name string `xml:"interface"`
	Address string `xml:"ip"`
}

func main() {
	var firewall string
	var user string
	var numAddresses int
	var password string

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Harvests pingable IP addresses from a firewall's ARP cache\n\n")
		fmt.Fprintf(os.Stderr, "USAGE: pan-pingable-hosts [options] <firewall>\n\n")
		fmt.Fprintf(os.Stderr, "EXAMPLES:\n")
		fmt.Fprintf(os.Stderr, "  > pan-pingable-hosts fw01.domain.com\n")
		fmt.Fprintf(os.Stderr, "  > pan-pingable-hosts -u user panwfw01.corp.com\n")
		fmt.Fprintf(os.Stderr, "  > pan-pingable-hosts -u user -n 4 panwfw01.corp.com\n\n")
		fmt.Fprintf(os.Stderr, "OPTIONS:\n")
		flag.PrintDefaults()
	}
	flag.StringVar(&user, "u", "", "User")
	flag.IntVar(&numAddresses, "n", 2, "Number of addresses per interface")
	flag.Parse()

	// Ensure the target firewall is defined, otherwise exit and display usage
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	} else {
		firewall = flag.Arg(0)
	}

	fmt.Fprintln(os.Stderr)
	if user == "" {
		fmt.Fprint(os.Stderr, "User: ")
		fmt.Scanln(&user)
	}

	fmt.Fprintf(os.Stderr, "Password (%s): ", user)
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	password = string(bytepw)
	fmt.Fprintf(os.Stderr, "\n\n")

	start := time.Now()
	data := getArpCache(firewall, user, password)
	var arpCache ArpCache
	err = xml.Unmarshal([]byte(data), &arpCache)
	if err != nil {
		panic(err)
	}

	// Create a map of interfaces with a slice of addresses
	interfaces := make(map[string][]string)
	for _, int := range arpCache.Entries {
		interfaces[int.Name] = append(interfaces[int.Name], int.Address)
	}

	// Harvest pingable addresses from each interface
	var pingableHosts []string
	for _, addrs := range interfaces {
		pingableHosts = append(pingableHosts, getPingableAddresses(addrs, numAddresses)...)
	}

	// Sort the pingableHosts slice
	pingableHostsSorted := make([]net.IP, 0, len(pingableHosts))
	for _, ip := range pingableHosts {
		pingableHostsSorted = append(pingableHostsSorted, net.ParseIP(ip))
	}
	sort.Slice(pingableHostsSorted, func(i int, j int) bool {
		return bytes.Compare(pingableHostsSorted[i], pingableHostsSorted[j]) < 0
	})

	// Print results
	for _, addr := range pingableHostsSorted {
		fmt.Println(addr)
	}
	fmt.Fprintln(os.Stderr)

	// Print summary
	elapsed := time.Since(start)
	fmt.Fprintf(os.Stderr, " Collection complete: Discovered %d pingable addresses in %.3f seconds\n", len(pingableHosts), elapsed.Seconds())
}

func getPingableAddresses(addrs []string, numAddrs int) []string {
	var pingableAddrs []string

	for _, addr := range addrs {
		// If ip addr begins with 0 skip iteration
		if strings.HasPrefix(addr, "0") {
			continue
		}

		// Ping ip addr and add to pingableAddrs if a response is received
		stats := pingAddr(addr)
		if stats.PacketLoss == 0 {
			pingableAddrs = append(pingableAddrs, addr)
		}

		// skip remaining addrs if pingableAddrs is eqaul to numAddrs
		if len(pingableAddrs) == numAddrs {
			break
		}
	}

	return pingableAddrs
}

func pingAddr(addr string) *ping.Statistics {
	// ping ip addr

	pinger, err := ping.NewPinger(addr)
	if err != nil {
		panic(err)
	}

	pinger.SetPrivileged(true)
	pinger.Timeout = time.Duration(50 * time.Millisecond)
	pinger.Count = 1

	err = pinger.Run()
	if err != nil {
		log.Fatalf("ICMP socket operations require 'sudo'\n")
	}

	stats := pinger.Statistics()

	return stats
}

func getArpCache(fw string, user string, pw string) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", fw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	creds := fmt.Sprintf("%s:%s", user, pw)
	credsEnc := base64.StdEncoding.EncodeToString([]byte(creds))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credsEnc))

	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><arp><entry name = 'all'/></arp></show>")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return string(respBody)
}
