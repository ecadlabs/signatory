package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMap(t *testing.T) {
	type testCase struct {
		s      string
		r1, r2 rune
		m      map[string]string
		e      string
	}

	var testCases = []testCase{
		{
			s:  "\t\tname1 value1 name2 value2",
			r1: -1,
			r2: -1,
			m:  map[string]string{"name1": "value1", "name2": "value2"},
		},
		{
			s:  "name1:value1 \nname2:value2 ",
			r1: ':',
			r2: -1,
			m:  map[string]string{"name1": "value1", "name2": "value2"},
		},
		{
			s:  "name1 $ value1 \nname2:value2 ",
			r1: ':',
			r2: -1,
			e:  "unexpected character: $",
		},
		{
			s:  "name\\ 1:\"value 1\" \nname2:value2 ",
			r1: ':',
			r2: -1,
			m:  map[string]string{"name 1": "value 1", "name2": "value2"},
		},
		{
			s:  " name1:value1, name2:value2 ",
			r1: ':',
			r2: ',',
			m:  map[string]string{"name1": "value1", "name2": "value2"},
		},
		{
			s:  " name1:value1, name2:value2 , ",
			r1: ':',
			r2: ',',
			e:  "unexpected end of the string",
		},
	}

	for i, tst := range testCases {
		res, err := ParseMap(tst.s, tst.r1, tst.r2)
		if tst.e != "" {
			require.EqualError(t, err, tst.e, i)
		} else {
			require.NoError(t, err, i)
		}
		require.Equal(t, tst.m, res, i)
	}
}
