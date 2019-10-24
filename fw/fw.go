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
	"flag"
	"log"
	// "net"
	"encoding/binary"
	"os"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/sirupsen/logrus"
)

func convertToBytes(n int) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(n))
	return buf
}

func main() {
	ifname := flag.String("i", "", "the name of the network interface")
	ipAddr := flag.String("s", "", "specify source ip address")
	rm := flag.Bool("rm", false, "remove filter from network interface, interface name must be specified")
	port := flag.Int("p", 0, "specify source port")
	flag.Parse()
	if *rm {
		if *ifname == "" {
			flag.Usage()
			os.Exit(1)
		}
		m := bpf.Module{}
		err := m.RemoveXDP(*ifname)
		if err != nil {
			logrus.Fatal(err)
		}
		return
	}
	if *ifname == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *ipAddr == "" && *port == 0 {
		flag.Usage()
		os.Exit(1)
	}
	m := bpf.NewModule(Source, []string{
		"-w",
	})
	if m == nil {
		log.Fatal("failed to initialize bpf module")
	}
	defer m.Close()
	fd, err := m.Load("filter", C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		log.Fatal(err)
	}
	err = m.AttachXDP(*ifname, fd)
	if err != nil {
		log.Fatal(err)
	}
	// This thing makes an error
	// defer m.RemoveXDP(*ifname)

	// ipAddrs := bpf.NewTable(m.TableId("ipAddrs"), m)
	// sPorts := bpf.NewTable(m.TableId("sPorts"), m)
	// if *ipAddr != "" {
	// 	ip := net.ParseIP(*ipAddr).To4()
	// 	if len(ip) == 0 {
	// 		log.Fatal("invalid ip address specified")
	// 	}
	// 	err = ipAddrs.Set(ip[:], []byte{0})
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// }

	// err = sPorts.Set(convertToBytes(*port), []byte{0})
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// if len(os.Args) < 2 {
	// 	log.Fatal("cidr mask is expected as an argument")
	// }
	// ip, ipNet, err := net.ParseCIDR(os.Args[1])
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// logrus.Infoln(ip, ipNet)
	// logrus.Infoln("ip len: ", len(ip))
	// for _, b := range ip {
	// 	fmt.Printf("%v ", b)
	// }
	// fmt.Println()
	// logrus.Infoln("ipNet ip len: ", len(ipNet.IP))
	// for _, b := range ipNet.IP {
	// 	fmt.Printf("%v ", b)
	// }
	// fmt.Println()
	// logrus.Infoln("ipNet mask len: ", len(ipNet.Mask))
	// for _, b := range ipNet.Mask {
	// 	fmt.Printf("%v ", b)
	// }
	// fmt.Println()
	// fmt.Printf("%b.%b.%b.%b\n", 192, 168, 0, 0)
	// i := int(ipNet.Mask[len(ipNet.Mask)-1]) << 1
	// i := 255
	// i = i << 1
	// logrus.Infoln(i)

}
