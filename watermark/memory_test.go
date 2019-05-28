package watermark_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ecadlabs/signatory/watermark"
)

func TestGetSigAlg(t *testing.T) {

	type CaseData struct {
		msgID string
		level string
	}

	type Case struct {
		Name     string
		data     []CaseData
		expected bool
	}

	cases := []Case{
		Case{Name: "Standard", data: []CaseData{CaseData{level: "1", msgID: "123"}}, expected: true},
		Case{Name: "Standard different message ID", data: []CaseData{CaseData{level: "1", msgID: "123"}, CaseData{level: "1", msgID: "124"}}, expected: true},
		Case{Name: "Standard Multiple", data: []CaseData{CaseData{level: "1", msgID: "123"}, CaseData{level: "2", msgID: "123"}}, expected: true},
		Case{Name: "Not allowed negative level", data: []CaseData{CaseData{level: "1", msgID: "123"}, CaseData{level: "0", msgID: "123"}}, expected: false},
		Case{Name: "Not allowed", data: []CaseData{CaseData{level: "1", msgID: "123"}, CaseData{level: "1", msgID: "123"}}, expected: false},
		Case{Name: "Not allowed nil level", data: []CaseData{CaseData{level: "", msgID: "123"}}, expected: false},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			m := watermark.NewMemory()
			var res bool
			for _, d := range c.data {
				i, _ := new(big.Int).SetString(d.level, 10)
				res = m.IsSafeToSign(d.msgID, i)
			}

			if c.expected != res {
				fmt.Printf("Expected %v but got %v\n", c.expected, res)
				t.Fail()
			}
		})
	}
}
