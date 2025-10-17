package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

var speculosBaseUrl string = "http://localhost:5001/"

// this is not a test of the tezos wallet app
func SpeculosApprove() {
	approve()
}

func approve() {
	//wait for the screen to say Operation
	var counter = 0
	for {
		counter++
		if counter > 1000 {
			panic("speculos approver: waiting for test pre-conditions. it's taking too long")
		}
		if strings.Contains(getScreenText(), "Operation") {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	//click right until it says APPROVE
	counter = 0
	for {
		counter++
		if counter > 2000 {
			panic("speculos approver: did not find APPROVE in 20 clicks right")
		}
		click("right")
		time.Sleep(time.Millisecond * 10)
		if strings.Contains(getScreenText(), "APPROVE") {
			break
		}
	}
	click("both")
}

func getScreenText() string {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, speculosBaseUrl+"events?currentscreenonly=true", nil)
	if err != nil {
		panic(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}

// use one of {"left", "both", "right"}
func click(button string) {
	client := &http.Client{}
	body := make(map[string]string)
	body["action"] = "press-and-release"
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest(http.MethodPost, speculosBaseUrl+"button/"+button, bytes.NewReader(b))
	if err != nil {
		panic(err)
	}
	_, err = client.Do(req)
	if err != nil {
		panic(err)
	}
}
