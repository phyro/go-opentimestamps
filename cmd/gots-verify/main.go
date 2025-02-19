package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/phyro/go-opentimestamps/opentimestamps"
	"github.com/phyro/go-opentimestamps/opentimestamps/client"
)

func newBtcConn(host, user, pass string) (*rpcclient.Client, error) {
	connCfg := &rpcclient.ConnConfig{
		Host:         host,
		User:         user,
		Pass:         pass,
		HTTPPostMode: true,
		DisableTLS:   true,
	}
	return rpcclient.New(connCfg, nil)
}

var (
	flagBTCHost = flag.String("btc-host", "localhost:8332", "bitcoin-rpc hostname")
	flagBTCUser = flag.String("btc-user", "bitcoin", "bitcoin-rpc username")
	flagBTCPass = flag.String("btc-pass", "bitcoin", "bitcoin-rpc password")
)

func main() {
	flag.Parse()
	path := flag.Arg(0)
	dts, err := opentimestamps.NewDetachedTimestampFromPath(path)
	if err != nil {
		log.Fatalf("error reading %s: %v", path, err)
	}

	btcConn, err := newBtcConn(*flagBTCHost, *flagBTCUser, *flagBTCPass)
	if err != nil {
		log.Fatalf("error creating btc connection: %v", err)
	}

	verifier := client.NewBitcoinAttestationVerifier(btcConn)

	ts, err := verifier.Verify(dts.Timestamp)
	if err != nil {
		log.Fatalf("error verifying timestamp: %v", err)
	}
	if ts == nil {
		fmt.Printf("no bitcoin-verifiable timestamps found\n")
	}
	fmt.Printf("attested time: %v\n", ts)
}
