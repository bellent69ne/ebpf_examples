package main

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/urfave/cli"
)

type blackListRaw struct {
	IPAddrs []string
	Hosts   []string
}

func BlackListed() ([]net.IP, error) {
	f, err := os.Open("rogue_blacklist.json")
	if err != nil {
		return nil, err
	}
	var blr blackListRaw
	err = json.NewDecoder(f).Decode(&blr)
	if err != nil {
		return nil, err
	}
	ipAddrs := []net.IP{}
	for _, addr := range blr.IPAddrs {
		ip := net.ParseIP(addr).To4()
		if ip == nil {
			return nil, fmt.Errorf("%s is an IPv6 address, IPv4 address expected", addr)
		}
		ipAddrs = append(ipAddrs, ip)
	}
	for _, host := range blr.Hosts {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, err
		}
		fmt.Println(addrs)
		for _, addr := range addrs {
			ip := net.ParseIP(addr).To4()
			if ip != nil {
				fmt.Println(host, ip)
				ipAddrs = append(ipAddrs, ip)
			}
		}
	}
	return ipAddrs, nil
}

func start(c *cli.Context) {
	if !c.Args().Present() {
		err := cli.ShowSubcommandHelp(c)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(1)
	}
	ipAddrs, err := BlackListed()
	if err != nil {
		log.Fatal(err)
	}
	m := bpf.NewModule(Source, []string{
		"-w",
	})
	if m == nil {
		log.Fatal("failed to initialize bpf module")
	}
	defer m.Close()
	fd, err := m.Load("filter", C.BPF_PROG_TYPE_XDP, 1, 200000)
	if err != nil {
		log.Fatal(err)
	}
	err = m.AttachXDP(c.Args().First(), fd)
	if err != nil {
		log.Fatal(err)
	}
	subnets := bpf.NewTable(m.TableId("ipv4"), m)
	for _, ip := range ipAddrs {
		err := subnets.Set(ip[:], []byte{1})
		if err != nil {
			log.Fatal(err)
		}
	}
}

func stop(c *cli.Context) {
	if !c.Args().Present() {
		err := cli.ShowSubcommandHelp(c)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(1)
	}
	m := bpf.Module{}
	err := m.RemoveXDP(c.Args().First())
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "rogue"
	app.Author = "Jem Maratov"
	app.Version = "1.0.0"
	app.Commands = []cli.Command{
		{
			Name:   "start",
			Usage:  "start IFNAME",
			Action: start,
		},
		{
			Name:   "stop",
			Usage:  "stop IFNAME",
			Action: stop,
		},
	}
	app.Run(os.Args)
}
