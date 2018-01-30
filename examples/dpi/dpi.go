package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

// Sample input pcap files can be downloaded from http://wiresharkbook.com/studyguide.html
// Test samples:
// http-cnn2012.pcapng
// http-facebook.pcapng
// http-downloadvideo.pcapng
// google-http.pcapng
//
// Note: only pcap format is supported. Convert pcapng to pcap:
// editcap -F pcap http-facebook.pcapng http-facebook.pcap

const (
	// Last flow among totalNumFlows is for dropped packets
	totalNumFlows uint = 5
	numFlows      uint = totalNumFlows - 1
)

var (
	// Number of allowed packets for each flow
	allowedPktsCount [numFlows]uint64
	// Number of read packets for each flow
	readPktsCount [numFlows]uint64
	// Number of packets blocked by signature for each flow
	blockedPktsCount [numFlows]uint64
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

type rule struct {
	name  string
	re    *regexp.Regexp
	allow bool
}

// Rules must be in increasing priority. Each next rule is more specific and may complete (or overwrite) result of previous rules check.
var rules = []rule{
	// Allowed signatures
	rule{name: "Facebook", re: regexp.MustCompile("Host: [a-z-]*.facebook.com"), allow: true},
	rule{name: "Netflix", re: regexp.MustCompile("Host: [a-z-]*netflix[0-9a-z.]*nflximg.com"), allow: true},
	rule{name: "VideoDownl", re: regexp.MustCompile("Content-Type: video"), allow: true},
	rule{name: "GoodHTTP", re: regexp.MustCompile("Content-Type: (text/html|text/css|image)"), allow: true},
	// Blocked signatures
	rule{name: "BlockJavaScriptAppType", re: regexp.MustCompile("Content-Type: application/(x-|)javascript"), allow: false},
	rule{name: "BlockJavaScriptInHTML", re: regexp.MustCompile("((<[\\s\\/]*script\\b[^>]*>)([^>]*)(<\\/script>))"), allow: false},
}

func main() {
	infile := flag.String("infile", "", "input pcap file")
	outfile := flag.String("outfile", "hsdpi_allowed.pcap", "output pcap file with allowed packets")
	nreads := flag.Int("nreads", 1, "number pcap file reads")
	timeout := flag.Duration("timeout", 10*time.Second, "time to run in seconds")
	flag.Parse()

	// Initialize NFF-Go library
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	// Receive packets from given PCAP file
	inputFlow := flow.SetReceiverFile(*infile, int32(*nreads))

	// Split packets into flows by hash of five-tuple
	// Packets without five-tuple are put in last flow and will be dropped
	outputFlows, err := flow.SetSplitter(inputFlow, splitBy5Tuple, totalNumFlows, nil)
	CheckFatal(err)

	// Drop last flow
	CheckFatal(flow.SetStopper(outputFlows[totalNumFlows-1]))

	for i := uint(0); i < numFlows; i++ {
		lc := localCounters{handlerId: i}
		CheckFatal(flow.SetHandlerDrop(outputFlows[i], filterPackets, lc))
	}

	outFlow, err := flow.SetMerger(outputFlows[:numFlows]...)
	CheckFatal(err)

	CheckFatal(flow.SetSenderFile(outFlow, *outfile))

	go func() {
		CheckFatal(flow.SystemStart())
	}()

	// Finish by timeout, as cannot verify if file reading finished
	time.Sleep(*timeout)

	// Compose info about all handlers
	var read uint64
	var allowed uint64
	var blocked uint64
	fmt.Println("\nHandler statistics")
	for i := uint(0); i < numFlows; i++ {
		fmt.Printf("Handler %d processed %d packets (allowed=%d, blocked by signature=%d)\n",
			i, readPktsCount[i], allowedPktsCount[i], blockedPktsCount[i])
		read += readPktsCount[i]
		allowed += allowedPktsCount[i]
		blocked += blockedPktsCount[i]
	}
	fmt.Println("Total:")
	fmt.Println("read =", read)
	fmt.Println("allowed =", allowed)
	fmt.Println("blocked =", blocked)
	fmt.Println("dropped (read - allowed) =", read-allowed)
}

type localCounters struct {
	handlerId         uint
	allowedCounterPtr *uint64
	readCounterPtr    *uint64
	blockedCounterPtr *uint64
}

// Create new counters for new handler
func (lc localCounters) Copy() interface{} {
	var newlc localCounters
	// Clones has the same id
	id := lc.handlerId
	newlc.handlerId = id
	newlc.allowedCounterPtr = &allowedPktsCount[id]
	newlc.readCounterPtr = &readPktsCount[id]
	newlc.blockedCounterPtr = &blockedPktsCount[id]
	return newlc
}

func (lc localCounters) Delete() {
}

func filterPackets(pkt *packet.Packet, context flow.UserContext) bool {
	cnt := context.(localCounters)
	numRead := cnt.readCounterPtr
	numAllowed := cnt.allowedCounterPtr
	numBlocked := cnt.blockedCounterPtr

	atomic.AddUint64(numRead, 1)
	data := extractData(pkt)
	accept := false

	for _, rule := range rules {
		result := rule.re.Match(data)
		if !result {
			continue
		}
		if rule.allow {
			accept = true
		} else {
			accept = false
			atomic.AddUint64(numBlocked, 1)
		}
	}
	if accept {
		atomic.AddUint64(numAllowed, 1)
	}
	return accept
}

func splitBy5Tuple(pkt *packet.Packet, context flow.UserContext) uint {
	h := fnv.New64a()
	ip4, ip6, _ := pkt.ParseAllKnownL3()
	if ip4 != nil {
		pkt.ParseL4ForIPv4()
	} else if ip6 != nil {
		pkt.ParseL4ForIPv6()
	} else {
		// Other protocols not supported
		return totalNumFlows - 1
	}

	if ip4 != nil {
		binary.Write(h, binary.BigEndian, ip4.NextProtoID)
		buf := new(bytes.Buffer)
		CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.SrcAddr))
		h.Write(buf.Bytes())
		CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.DstAddr))
		h.Write(buf.Bytes())
	} else if ip6 != nil {
		binary.Write(h, binary.BigEndian, ip6.Proto)
		h.Write(ip6.SrcAddr[:])
		h.Write(ip6.DstAddr[:])
	}
	binary.Write(h, binary.BigEndian, pkt.GetTCPNoCheck().SrcPort)
	binary.Write(h, binary.BigEndian, pkt.GetTCPNoCheck().DstPort)

	hash := uint(h.Sum64())
	return hash % numFlows
}

func extractData(pkt *packet.Packet) []byte {
	pktLen := pkt.GetPacketSegmentLen()
	pktStartAddr := pkt.StartAtOffset(0)
	pktBytes := (*[1 << 30]byte)(pktStartAddr)[:pktLen]
	pkt.ParseData()

	hdrsLen := uintptr(pkt.Data) - uintptr(pktStartAddr)
	return pktBytes[hdrsLen:]
}
