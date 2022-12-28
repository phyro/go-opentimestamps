package client

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/phyro/go-opentimestamps/opentimestamps"
)

// A BitcoinAttestationVerifier uses a bitcoin RPC connection to verify bitcoin
// headers.
type BitcoinAttestationVerifier struct {
	rpcClient *rpcclient.Client
}

func NewBitcoinAttestationVerifier(
	c *rpcclient.Client,
) *BitcoinAttestationVerifier {
	return &BitcoinAttestationVerifier{c}
}

func b2lx(b []byte) string {
	// Reverse the slice
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	// Encode the reversed slice as a hex string
	return hex.EncodeToString(b)
}

// VerifyAttestation checks a BitcoinAttestation using a given hash digest. It
// returns the time of the block if the verification succeeds, an error
// otherwise.
func (v *BitcoinAttestationVerifier) VerifyAttestation(
	digest []byte, a *opentimestamps.BitcoinAttestation,
) (*time.Time, error) {
	fmt.Printf("\nHeight: %d", a.Height)
	fmt.Printf("\nHeight int: %d", int64(a.Height))
	fmt.Printf("\nDigest: %s", string(digest))
	fmt.Printf("\nDigest hex: %s", hex.EncodeToString(digest))
	// fmt.Printf("\nb2lx\b: %s", b2lx(digest))
	// // TMP: check manually
	// merkleroot := []byte("7899208982c5465429d4ae10822347d570a7428b3d3b4282ff8891c631f68395")
	// err1 := a.VerifyAgainstBlockHash(digest, merkleroot)
	// if err1 != nil {
	// 	return nil, err1
	// }

	if a.Height > math.MaxInt64 {
		return nil, fmt.Errorf("illegal block height")
	}
	blockHash, err := v.rpcClient.GetBlockHash(int64(a.Height))
	if err != nil {
		return nil, err
	}
	h, err := v.rpcClient.GetBlockHeader(blockHash)
	if err != nil {
		return nil, err
	}

	merkleRootBytes := h.MerkleRoot[:]
	// fmt.Printf("\nBlock hash: %s", &blockHash)
	fmt.Printf("\nDigest hex: %s", hex.EncodeToString(digest))
	fmt.Printf("\nMerkle root: %s", hex.EncodeToString(merkleRootBytes))

	err = a.VerifyAgainstBlockHash(digest, merkleRootBytes)
	if err != nil {
		return nil, err
	}
	utc := h.Timestamp.UTC()

	return &utc, nil
}

// A BitcoinVerification is the result of verifying a BitcoinAttestation
type BitcoinVerification struct {
	Timestamp       *opentimestamps.Timestamp
	Attestation     *opentimestamps.BitcoinAttestation
	AttestationTime *time.Time
	Error           error
}

// BitcoinVerifications returns the all bitcoin attestation results for the
// timestamp.
func (v *BitcoinAttestationVerifier) BitcoinVerifications(
	t *opentimestamps.Timestamp,
) (res []BitcoinVerification) {
	t.Walk(func(ts *opentimestamps.Timestamp) {
		for _, att := range ts.Attestations {
			btcAtt, ok := att.(*opentimestamps.BitcoinAttestation)
			if !ok {
				continue
			}
			attTime, err := v.VerifyAttestation(ts.Message, btcAtt)
			res = append(res, BitcoinVerification{
				Timestamp:       ts,
				Attestation:     btcAtt,
				AttestationTime: attTime,
				Error:           err,
			})
		}
	})
	return res
}

// Verify returns the earliest bitcoin-attested time, or nil if none can be
// found or verified successfully.
func (v *BitcoinAttestationVerifier) Verify(
	t *opentimestamps.Timestamp,
) (ret *time.Time, err error) {
	res := v.BitcoinVerifications(t)
	for _, r := range res {
		if r.Error != nil {
			err = r.Error
			continue
		}
		if ret == nil || r.AttestationTime.Before(*ret) {
			ret = r.AttestationTime
		}
	}
	return
}
