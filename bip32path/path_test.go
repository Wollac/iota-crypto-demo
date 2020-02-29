package bip32path

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePath(t *testing.T) {
	var tests = []struct {
		s    string
		path BIPPath
		err  error
	}{
		{"", BIPPath{}, nil},
		{"m", BIPPath{}, nil},
		{"m/0H", BIPPath{hardened + 0}, nil},
		{"m/0H/1", BIPPath{hardened + 0, 1}, nil},
		{"m/0H/1/2H", BIPPath{hardened + 0, 1, hardened + 2}, nil},
		{"m/0H/1/2H/2", BIPPath{hardened + 0, 1, hardened + 2, 2}, nil},
		{"m/0H/1/2H/2/1000000000", BIPPath{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
		{"0H", BIPPath{hardened + 0}, nil},
		{"0H/1", BIPPath{hardened + 0, 1}, nil},
		{"0H/1/2H", BIPPath{hardened + 0, 1, hardened + 2}, nil},
		{"0H/1/2H/2", BIPPath{hardened + 0, 1, hardened + 2, 2}, nil},
		{"0H/1/2H/2/1000000000", BIPPath{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
		{"m/0'", BIPPath{hardened + 0}, nil},
		{"m/0'/1", BIPPath{hardened + 0, 1}, nil},
		{"m/0'/1/2'", BIPPath{hardened + 0, 1, hardened + 2}, nil},
		{"m/0'/1/2'/2", BIPPath{hardened + 0, 1, hardened + 2, 2}, nil},
		{"m/0'/1/2'/2/1000000000", BIPPath{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
		{"0'", BIPPath{hardened + 0}, nil},
		{"0'/1", BIPPath{hardened + 0, 1}, nil},
		{"0'/1/2'", BIPPath{hardened + 0, 1, hardened + 2}, nil},
		{"0'/1/2'/2", BIPPath{hardened + 0, 1, hardened + 2, 2}, nil},
		{"0'/1/2'/2/1000000000", BIPPath{hardened + 0, 1, hardened + 2, 2, 1000000000}, nil},
		{"0/2147483647'/1/2147483646'/2", BIPPath{0, hardened + 2147483647, 1, hardened + 2147483646, 2}, nil},
		{"0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0", BIPPath{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil},
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

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.s, "/", "|"), func(t *testing.T) {
			path, err := ParsePath(tt.s)
			assert.Equal(t, tt.path, path)
			assert.True(t, errors.Is(err, tt.err), "unexpected error: %v", err)
		})
	}
}

func TestBIPPath_String(t *testing.T) {
	var tests = []struct {
		s string
	}{
		{"m"},
		{"m/0'"},
		{"m/0'/1"},
		{"m/0'/1/2'"},
		{"m/0'/1/2'/2"},
		{"m/0'/1/2'/2/1000000000"},
	}

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.s, "/", "|"), func(t *testing.T) {
			path, err := ParsePath(tt.s)
			require.NoError(t, err)
			assert.Equal(t, tt.s, path.String())
		})
	}
}
