package bundle

import (
	"crypto/ed25519"
	"errors"

	"github.com/iotaledger/iota.go/bundle"
	"github.com/iotaledger/iota.go/transaction"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-bip39-demo/pkg/ed25519/address"
	"github.com/wollac/iota-bip39-demo/pkg/ed25519/sign"
)

var (
	ErrNoOutput            = errors.New("at least one output required")
	ErrIntegerOverflow     = errors.New("integer overflow")
	ErrInsufficientBalance = errors.New("insufficient balance")
)

type (
	Transfer  = bundle.Transfer
	Transfers = bundle.Transfers

	Input struct {
		KeyPair ed25519.PrivateKey
		Value   uint64
		Tag     trinary.Trytes
	}
)

func ValidateSignature(txs bundle.Bundle) (bool, error) {
	for i := range txs {
		// skip non-inputs
		if txs[i].Value >= 0 {
			continue
		}
		valid, err := sign.Verify(txs[i].Address, txs[i].SignatureMessageFragment, txs[i].Bundle)
		if err != nil || !valid {
			return false, err
		}
	}
	return true, nil
}

func Generate(transfers []bundle.Transfer, inputs []Input, txTimestamp uint64) (transaction.Transactions, error) {
	if len(transfers) < 1 {
		return nil, ErrNoOutput
	}

	// create the bundle
	txs := transaction.Transactions{}

	outEntries, err := bundle.TransfersToBundleEntries(txTimestamp, transfers...)
	if err != nil {
		return nil, err
	}
	for i := range outEntries {
		txs = bundle.AddEntry(txs, outEntries[i])
	}

	var inputIndices []int
	for _, input := range inputs {
		inputIndices = append(inputIndices, len(txs))

		inAddress, err := address.Generate(input.KeyPair)
		if err != nil {
			return nil, err
		}
		entry := bundle.BundleEntry{
			Length:                    1,
			Address:                   inAddress,
			Value:                     -int64(input.Value),
			Tag:                       input.Tag,
			Timestamp:                 txTimestamp,
			SignatureMessageFragments: nil,
		}
		txs = bundle.AddEntry(txs, entry)
	}

	// validate balance
	totalOutput, err := totalOutputValue(transfers)
	if err != nil {
		return nil, err
	}
	totalInput, err := totalInputValue(inputs)
	if err != nil {
		return nil, err
	}
	if totalOutput != totalInput {
		return nil, ErrInsufficientBalance
	}

	// finalize bundle by adding the bundle hash
	// TODO: do not do mini-PoW
	txs, err = bundle.Finalize(txs)
	if err != nil {
		return nil, err
	}

	// add signature fragments
	for i := range inputs {
		idx := inputIndices[i]
		signedFrag, err := sign.Generate(inputs[i].KeyPair, txs[idx].Bundle)
		if err != nil {
			return nil, err
		}
		txs[idx].SignatureMessageFragment = signedFrag
	}

	return txs, nil
}

func totalOutputValue(transfers []bundle.Transfer) (uint64, error) {
	var totalOutput uint64
	for i := range transfers {
		var ok bool
		totalOutput, ok = add(totalOutput, transfers[i].Value)
		if !ok {
			return 0, ErrIntegerOverflow
		}
	}
	return totalOutput, nil
}

func totalInputValue(inputs []Input) (uint64, error) {
	var totalInput uint64
	for i := range inputs {
		var ok bool
		totalInput, ok = add(totalInput, inputs[i].Value)
		if !ok {
			return 0, ErrIntegerOverflow
		}
	}
	return totalInput, nil
}

// add with overflow protection
func add(a, b uint64) (c uint64, ok bool) {
	c = a + b
	if c >= a {
		ok = true
	}
	return
}
