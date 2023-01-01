package client

import (
	"encoding/hex"
	"errors"
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

// VerifyAttestation checks a BitcoinAttestation using a given hash digest. It
// returns the time of the block if the verification succeeds, an error
// otherwise.
func (v *BitcoinAttestationVerifier) VerifyAttestation(
	digest []byte, a *opentimestamps.BitcoinAttestation,
) (*time.Time, error) {
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
	err = a.VerifyAgainstBlockHash(digest, merkleRootBytes)
	if err != nil {
		fmt.Printf("\nHeight: %d", a.Height)
		fmt.Printf("\nHeight int: %d", int64(a.Height))
		fmt.Printf("\nDigest: %s", string(digest))
		fmt.Printf("\nDigest hex: %s", hex.EncodeToString(digest))
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

// A BitcoinVerificationManual holds data needed for manual verification
type BitcoinVerificationManual struct {
	// Attestation time is the block header timestamp
	Height             uint64
	ExpectedMerkleRoot []byte
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

// Verify returns pairs (height, expected_merkle_root) or nil.
func (v *BitcoinAttestationVerifier) VerifyManual(
	t *opentimestamps.Timestamp,
) ([]BitcoinVerificationManual, error) {
	res := v.BitcoinVerificationsManual(t)
	if len(res) == 0 {
		return nil, errors.New("No attestations found.")
	}
	return res, nil
}

// BitcoinVerificationsManual returns all bitcoin attestation pairs
// (height, expected_merkle_root)
func (v *BitcoinAttestationVerifier) BitcoinVerificationsManual(
	t *opentimestamps.Timestamp,
) []BitcoinVerificationManual {
	res := []BitcoinVerificationManual{}
	t.Walk(func(ts *opentimestamps.Timestamp) {
		for _, att := range ts.Attestations {
			btcAtt, ok := att.(*opentimestamps.BitcoinAttestation)
			if !ok {
				continue
			}
			res = append(res, BitcoinVerificationManual{
				Height:             btcAtt.Height,
				ExpectedMerkleRoot: ts.Message,
			})
		}
	})
	return res
}
