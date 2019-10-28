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
	Ports   []int
}
type BlackList struct {
	IPAddrs []net.IP
	Ports   []int
}

func BlackListed() (BlackList, error) {
	f, err := os.Open("rogue_blacklist.json")
	if err != nil {
		return BlackList{}, err
	}
	var blr blackListRaw
	err = json.NewDecoder(f).Decode(&blr)
	if err != nil {
		return BlackList{}, err
	}
	bl := BlackList{}
	for _, p := range blr.Ports {
		if p < 1 || p > 65536 {
			return BlackList{}, fmt.Errorf("%d port must be between 1 and 65536", p)
		}
	}
	bl.Ports = blr.Ports
	for _, addr := range blr.IPAddrs {
		ip := net.ParseIP(addr).To4()
		if ip == nil {
			return BlackList{}, fmt.Errorf("%s is an IPv6 address, IPv4 address expected", addr)
		}
		bl.IPAddrs = append(bl.IPAddrs, ip)
	}
	for _, host := range blr.Hosts {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return BlackList{}, err
		}
		fmt.Println(addrs)
		for _, addr := range addrs {
			ip := net.ParseIP(addr).To4()
			if ip != nil {
				fmt.Println(host, ip)
				bl.IPAddrs = append(bl.IPAddrs, ip)
			}
		}
	}
	return bl, nil
}

func convertToBytes(n int) []byte {
	buf := make([]byte, 2)
	// binary.LittleEndian.PutUint16(buf, uint16(n))
	return buf
}

func start(c *cli.Context) {
	if !c.Args().Present() {
		err := cli.ShowSubcommandHelp(c)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(1)
	}
	blacklist, err := BlackListed()
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
	for _, ip := range blacklist.IPAddrs {
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

//
// func drop(c *cli.Context) {
// 	if !c.Args().Present() {
// 		err := cli.ShowSubcommandHelp(c)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		os.Exit(1)
// 	}
// 	// m := bpf.Module{}
// 	m := bpf.NewModule(Source, []string{
// 		"-w",
// 	})
// 	if m == nil {
// 		log.Fatal("failed to initialize bpf module")
// 	}
// 	defer m.Close()
// 	fd, err := m.Load("filter", C.BPF_PROG_TYPE_XDP, 1, 200000)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	err = m.AttachXDP(c.Args().First(), fd)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	subnets := bpf.NewTable(m.TableId("subnets"), m)
// 	// sPorts := bpf.NewTable(m.TableId("sPorts"), m)
// 	saddr := c.String("saddr")
// 	if saddr != "" {
// 		ip := net.ParseIP(saddr).To4()
// 		if len(ip) == 0 {
// 			log.Fatal("invalid ip address specified")
// 		}
// 		err := subnets.Set(ip[:], []byte{1})
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 	}
// }

func main() {
	app := cli.NewApp()
	app.Name = "rogue"
	app.Author = "Jem Maratov"
	app.Version = "1.0.0"
	app.Commands = []cli.Command{
		{
			Name:   "start",
			Usage:  "starts filtering incoming traffic for the specified network interface",
			Action: start,
			// Flags: []cli.Flag{
			// 	cli.StringFlag{
			// 		Name:  "saddr",
			// 		Usage: "source ip address",
			// 	},
			// },
		},
		{
			Name:   "stop",
			Usage:  "stops filtering incoming traffic for the specified network interface",
			Action: stop,
		},
	}
	app.Run(os.Args)
}

// func main() {
// 	ifname := flag.String("i", "", "the name of the network interface")
// 	ipAddr := flag.String("s", "", "specify source ip address")
// 	rm := flag.Bool("rm", false, "remove filter from network interface, interface name must be specified")
// 	port := flag.Int("p", 0, "specify source port")
// 	flag.Parse()
// 	if *rm {
// 		if *ifname == "" {
// 			flag.Usage()
// 			os.Exit(1)
// 		}
// 		m := bpf.Module{}
// 		err := m.RemoveXDP(*ifname)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		return
// 	}
// 	if *ifname == "" {
// 		flag.Usage()
// 		os.Exit(1)
// 	}
// 	if *ipAddr == "" && *port == 0 {
// 		flag.Usage()
// 		os.Exit(1)
// 	}
// 	m := bpf.NewModule(Source, []string{
// 		"-w",
// 	})
// 	if m == nil {
// 		log.Fatal("failed to initialize bpf module")
// 	}
// 	defer m.Close()
// 	fd, err := m.Load("filter", C.BPF_PROG_TYPE_XDP, 1, 65536)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	err = m.AttachXDP(*ifname, fd)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// This thing makes an error
// 	// defer m.RemoveXDP(*ifname)
//
// 	subnets := bpf.NewTable(m.TableId("subnets"), m)
// 	// sPorts := bpf.NewTable(m.TableId("sPorts"), m)
// 	if *ipAddr != "" {
// 		ip := net.ParseIP(*ipAddr).To4()
// 		if len(ip) == 0 {
// 			log.Fatal("invalid ip address specified")
// 		}
// 		err = subnets.Set(ip[:], []byte{23})
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 	}
// 	// err = sPorts.Set(convertToBytes(*port), []byte{0})
// 	// if err != nil {
// 	// 	log.Fatal(err)
// 	// }
//
// 	// if len(os.Args) < 2 {
// 	// 	log.Fatal("cidr mask is expected as an argument")
// 	// }
// 	// ip, ipNet, err := net.ParseCIDR(os.Args[1])
// 	// if err != nil {
// 	// 	log.Fatal(err)
// 	// }
// 	// log.Infoln(ip, ipNet)
// 	// log.Infoln("ip len: ", len(ip))
// 	// for _, b := range ip {
// 	// 	fmt.Printf("%v ", b)
// 	// }
// 	// fmt.Println()
// 	// log.Infoln("ipNet ip len: ", len(ipNet.IP))
// 	// for _, b := range ipNet.IP {
// 	// 	fmt.Printf("%v ", b)
// 	// }
// 	// fmt.Println()
// 	// log.Infoln("ipNet mask len: ", len(ipNet.Mask))
// 	// for _, b := range ipNet.Mask {
// 	// 	fmt.Printf("%v ", b)
// 	// }
// 	// fmt.Println()
// 	// fmt.Printf("%b.%b.%b.%b\n", 192, 168, 0, 0)
// 	// i := int(ipNet.Mask[len(ipNet.Mask)-1]) << 1
// 	// i := 255
// 	// i = i << 1
// 	// log.Infoln(i)
//
// }
