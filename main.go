package main

import (
	"github.com/linn221/attacker/client"
	"github.com/linn221/attacker/fuzz"
)

// main builds an HTTP probe of example.com and hands it to the local job server.
// The gap is a min:max pause, in seconds, between requests.
func main() {
	client.NewJob("http://127.0.0.1:6423", "/home/linn/ex", "1:2", func(fz *fuzz.Fuzz) {
		fz.Https(true).
			DomainName("example.com").
			Method("GET").
			Uri("/")
		fz.AndFunc(fuzz.Uri("/", "/index.html", "/robots.txt"))
		fz.OrFunc(fuzz.AllMethods())
		fz.OrFunc(fuzz.ToggleHttps)
	})
}
