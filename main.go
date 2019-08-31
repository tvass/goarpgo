/*
go arp go !
A simple "arp watch" alt to learn golang.
Thomas

Usage: ./goarpgo --if eth0 [--db ~/.goarpgo/db.json] [--resolv x.x.x.x][--debug]

Sample output:
[+] 00:00:00:00:d5:0c    192.168.1.13    fedora.
[+] 00:00:00:00:f1:16    192.168.1.1     ControlPanel.
[+] 00:00:00:52:00:c3    192.168.1.7     ESP_0000C3.
[+] 00:00:00:e8:00:d9    192.168.1.10
...

[+] Device is new
[>] Device info changed (IP)
[=] No change detected. Only print in debug mode.

To do :
- Change static bpf filter to automatic (based on system config)
- Add --resolv to use custon resolver
- Write data in a local file (json?) (save state, load state, trash db)
- Listen on multiple interfaces
- Action on event (config via yaml ?)
- RPM spec with systemd units
*/

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type device struct {
	mac      string
	ipv4     string
	hostname string
}

var debug = false

func main() {
	var devices = make(map[string]device)
	ifName := flag.String("if", "", "specify string")
	flag.Parse()
	handle, err := pcap.OpenLive(*ifName, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("Error during openning device name", *ifName, " :", err)
		return
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var filter = "src net 192.168"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range packetSource.Packets() {
		mydevice := readPacket(packet)

		if _, ok := devices[mydevice.mac]; ok {
			var oldDevice = devices[mydevice.mac]
			if mydevice.ipv4 == oldDevice.ipv4 { //Should compare struct
				if debug {
					printDevice(mydevice, "nochange")
				}
			} else {
				if mydevice.ipv4 != "" {
					mydevice.hostname = resolvIP(mydevice.ipv4)
					devices[mydevice.mac] = mydevice
					printDevice(mydevice, "update")
				}
			}
		} else {
			mydevice.hostname = resolvIP(mydevice.ipv4)
			devices[mydevice.mac] = mydevice
			printDevice(mydevice, "new")
			notifySignal(mydevice)
		}
	}
}

func printDevice(mydevice device, event string) {
	var prefix string
	switch event {
	case "new":
		prefix = "[+]"
	case "update":
		prefix = "[>]"
	case "nochange":
		prefix = "[=]"
	}
	println(prefix, mydevice.mac, "\t", mydevice.ipv4, "\t", mydevice.hostname)
}

func resolvIP(ipaddr string) string {
	var hostname string
	ptr, _ := net.LookupAddr(ipaddr)
	hostname = strings.Join(ptr, " ")
	return hostname
}

func readPacket(packet gopacket.Packet) device {
	var mydevice device
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		mydevice.mac = ethernetPacket.SrcMAC.String()
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			mydevice.ipv4 = ip.SrcIP.String()
		}
	}
	return mydevice
}

func notifySignal(mydevice device) {
	var notif bytes.Buffer
	notif.WriteString("New device detected: ")
	notif.WriteString(mydevice.mac)
	notif.WriteString("\n")
	notif.WriteString("IP: ")
	notif.WriteString(mydevice.ipv4)
	notif.WriteString("\n")
	notif.WriteString("Hostname: ")
	notif.WriteString(mydevice.hostname)
	http.PostForm("http://192.168.1.3:5000", url.Values{"to": {"+1xxxxxxxxxx"}, "message": {notif.String()}})
}

func loadDB() {
}

func saveDB() {
}

func trashDB() {
}
