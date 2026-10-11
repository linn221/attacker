- [ ] helper function for filtering Headers, Cookies, BodyJson
- [ ] .NewBase() would start a whole new fuzz, independant of previous settings
- [ ] create random directory, add Title to JobModel
- [ ] response hash should combine with status code

- [ ] put the recent detail on top instead of bottom
- [ ] want a htmx polling for new results with the filers on
- [ ] include method name in url for table view of results



# Features
- [ ] move curl2cfg to attacker server
- [ ] monitor asset by adding requestHash to results
- [ ] add where field that would accept sql and use raw sql
- [ ] show response body, response headers, etc be autoloaded via htmx hx-trigger of load based on the presence of url queries such as showResponseHeaders=true, showResponseBody=true, etc.
- [ ] add mutate body function that will take the type as type parameter, mutating the parsed body, and then plugging back any type
- [ ] response headers should be studied, like which requests have which header
- [ ] want a detector for CORS related, Clickjacking bugs, any bugs that could be detected by the absence or misconfiguration of http headers