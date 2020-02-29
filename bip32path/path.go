package bip32path

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalidPathFormat is returned when a path string could not be parsed due to a different general structure.
var ErrInvalidPathFormat = errors.New("invalid path format")

// hardened denotes the first hardened index.
const hardened uint32 = 1 << 31

// keyReg is the regular expression for a single key.
var keyReg = regexp.MustCompile(`(\d+)([H']?)`) // any number of digits plus an optional H or '

// A BIPPath is a BIP-32 key derivation path, a slice of uint32.
type BIPPath []uint32

// ParsePath parses s as an BIP-32 path, returning the result.
// The string s can be in the form where the apostrophe means hardened key ("m/44'/0'/0'/0/0")
// or where "H" means hardened key ("m/44H/0H/0H/0/0"). The "m/" prefix is mandatory.
func ParsePath(s string) (BIPPath, error) {
	if s == "" || s == "m" {
		return BIPPath{}, nil
	}
	if strings.HasPrefix(s, "m/") {
		s = s[2:]
	}

	var path []uint32
	for i, key := range strings.Split(s, "/") {
		matches := keyReg.FindStringSubmatch(key)
		// check whether the entire key matches and there is a digit
		if len(matches) < 2 || matches[0] != key {
			return nil, fmt.Errorf("invalid key %d: %w", i, ErrInvalidPathFormat)
		}
		// parse the digits
		v, err := parseUint31(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid key %d: %w", i, err)
		}
		// the key is hardened if the second capture group was matched
		if len(matches) > 2 && len(matches[2]) > 0 {
			v |= hardened
		}
		path = append(path, v)
	}
	return path, nil
}

// String returns the string form of the BIP-32 path.
// It returns:
// - "m" for an empty path
// - apostrophe for hardened keys ("m/44'/0'/0'/0/0")
func (p BIPPath) String() string {
	var builder strings.Builder
	builder.WriteByte('m')

	for _, idx := range p {
		builder.WriteString(fmt.Sprintf("/%d", idx&^hardened))
		if idx >= hardened {
			builder.WriteByte('\'')
		}
	}
	return builder.String()
}

func parseUint31(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 31)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}
