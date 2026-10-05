package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/linn221/attacker/fuzz"
)

const SERVER_URL = "http://localhost:6423"

type jobMeta struct {
	Current int    `json:"current"`
	End     int    `json:"end"`
	Gap     string `json:"gap"`
}

func main() {
	dir := "/home/linn/oct5.3"
	gap := "10:20"
	base := fuzz.Shot{
		Https:      true,
		DomainName: "example.com",
		Uri:        "search",
		Queries:    make(map[string][]string),
		Headers:    make(map[string]string),
		Cookies:    make(map[string][]string),
	}
	fuzzer := fuzz.NewFuzzer(&base)
	fuzzer.AndFunc(fuzz.ToggleHttps)
	fuzzer.AndFunc(fuzz.AllMethods())
	fuzzer.AndFunc(fuzz.AddQuery("sqli", fuzz.SqliPayload("coffee")...))
	fuzzer.AndFunc(fuzz.ParameterPollutionQuery("sqli", "elephant"))
	shots := fuzzer.Fuzz()

	// write files
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatal(err)
	}
	var wg sync.WaitGroup
	for i, shot := range shots {
		wg.Go(func() {
			filename := fmt.Sprintf("%s/%d.json", dir, i+1)
			bs, err := json.Marshal(shot)
			if err != nil {
				fmt.Println(err)
				return
			}
			err = os.WriteFile(filename, bs, 0600)
			if err != nil {
				fmt.Println(err)
			}
		})
	}
	wg.Wait()
	meta, err := json.MarshalIndent(jobMeta{
		Current: 1,
		End:     len(shots),
		Gap:     gap,
	}, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(dir+"/meta.json", append(meta, '\n'), 0600)
	if err != nil {
		log.Fatal(err)
	}

	u, err := url.Parse(SERVER_URL + "/newjob")
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	q.Set("dir", dir)
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		log.Fatalf("newjob: %s: %s", resp.Status, msg)
	}
}
