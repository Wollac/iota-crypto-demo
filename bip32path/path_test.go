package bip32

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var parsePathTests = []*struct {
	s    string
	path Path
	err  error
}{
	{"", Path{}, nil},
	{"m", Path{}, nil},
	{"m/0H", Path{hardened + 0}, nil},
	{"m/0H/1", Path{hardened + 0, 1}, nil},
	{"m/0H/1/2H", Path{hardened + 0, 1, hardened + 2}, nil},
	{"m/0H/1/2H/2", Path{hardened + 0, 1, hardened + 2, 2}, nil},
	{"m/0H/1/2H/2/1000000000", Path{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
	{"0H", Path{hardened + 0}, nil},
	{"0H/1", Path{hardened + 0, 1}, nil},
	{"0H/1/2H", Path{hardened + 0, 1, hardened + 2}, nil},
	{"0H/1/2H/2", Path{hardened + 0, 1, hardened + 2, 2}, nil},
	{"0H/1/2H/2/1000000000", Path{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
	{"m/0'", Path{hardened + 0}, nil},
	{"m/0'/1", Path{hardened + 0, 1}, nil},
	{"m/0'/1/2'", Path{hardened + 0, 1, hardened + 2}, nil},
	{"m/0'/1/2'/2", Path{hardened + 0, 1, hardened + 2, 2}, nil},
	{"m/0'/1/2'/2/1000000000", Path{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
	{"0'", Path{hardened + 0}, nil},
	{"0'/1", Path{hardened + 0, 1}, nil},
	{"0'/1/2'", Path{hardened + 0, 1, hardened + 2}, nil},
	{"0'/1/2'/2", Path{hardened + 0, 1, hardened + 2, 2}, nil},
	{"0'/1/2'/2/1000000000", Path{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
	{"0/2147483647'/1/2147483646'/2", Path{0, hardened + 2147483647, 1, hardened + 2147483646, 2}, nil},
	{"0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0", Path{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil},
	{"44'/2147483648", nil, strconv.ErrRange},
	{"44'/2147483648'", nil, strconv.ErrRange},
	{"44'/-1", nil, ErrInvalidPathFormat},
	{"44'//0", nil, ErrInvalidPathFormat},
	{"/0'/1/2'", nil, ErrInvalidPathFormat},
	{"44'/'", nil, ErrInvalidPathFormat},
	{"44'/'0", nil, ErrInvalidPathFormat},
	{"44'/0h", nil, ErrInvalidPathFormat},
	{"44'/0''", nil, ErrInvalidPathFormat},
	{"44'/0H'", nil, ErrInvalidPathFormat},
	{"wrong", nil, ErrInvalidPathFormat},
}

func TestParsePath(t *testing.T) {
	for _, tt := range parsePathTests {
		t.Run(strings.ReplaceAll(tt.s, "/", "|"), func(t *testing.T) {
			path, err := ParsePath(tt.s)
			assert.Equal(t, tt.path, path)
			assert.True(t, errors.Is(err, tt.err), "unexpected error: %v", err)
		})
	}
}

func TestBIPPathUnmarshalText(t *testing.T) {
	for _, tt := range parsePathTests {
		t.Run(strings.ReplaceAll(tt.s, "/", "|"), func(t *testing.T) {
			var path Path
			err := path.UnmarshalText([]byte(tt.s))
			assert.Equal(t, tt.path, path)
			assert.True(t, errors.Is(err, tt.err), "unexpected error: %v", err)
		})
	}
}

var bipPathStringTests = []*struct {
	s string
}{
	{"m"},
	{"m/0'"},
	{"m/0'/1"},
	{"m/0'/1/2'"},
	{"m/0'/1/2'/2"},
	{"m/0'/1/2'/2/1000000000"},
}

func TestBIPPathString(t *testing.T) {
	for _, tt := range bipPathStringTests {
		t.Run(strings.ReplaceAll(tt.s, "/", "|"), func(t *testing.T) {
			path, err := ParsePath(tt.s)
			require.NoError(t, err)
			assert.Equal(t, tt.s, path.String())
		})
	}
}

func TestBIPPathMarshalText(t *testing.T) {
	for _, tt := range bipPathStringTests {
		t.Run(strings.ReplaceAll(tt.s, "/", "|"), func(t *testing.T) {
			path, err := ParsePath(tt.s)
			require.NoError(t, err)

			b, err := path.MarshalText()
			require.NoError(t, err)
			assert.Equal(t, []byte(tt.s), b)
		})
	}
}
