package fuzz

import "strings"

func AdminCookies(s Shot) []Shot {
	values := []string{
		"is_admin=true",
		"is_admin=1",
		"admin=true",
		"admin=1",
		"role=admin",
		"user_role=admin",
		"administrator=true",
		"administrator=1",
	}

	return vary(values, func(s Shot, v string) Shot {
		parts := strings.SplitN(v, "=", 2)

		if s.Cookies == nil {
			s.Cookies = make(map[string][]string)
		}

		s.Cookies[parts[0]] = []string{parts[1]}

		return s
	})(s)
}

func AdminHeaders(s Shot) []Shot {
	values := []string{
		"X-Admin=true",
		"X-Admin=1",
		"X-Is-Admin=true",
		"X-Is-Admin=1",
		"X-Role=admin",
		"X-User-Role=admin",
		"X-Authenticated=true",
		"X-Forwarded-User=admin",
	}

	return vary(values, func(s Shot, v string) Shot {
		parts := strings.SplitN(v, "=", 2)

		s.Headers = cloneHeaders(s.Headers)
		s.Headers[parts[0]] = []string{parts[1]}

		return s
	})(s)
}

func AdminQueries(s Shot) []Shot {
	values := []string{
		"is_admin=true",
		"is_admin=1",
		"admin=true",
		"admin=1",
		"role=admin",
		"user_role=admin",
		"administrator=true",
		"administrator=1",
	}

	return vary(values, func(s Shot, v string) Shot {
		parts := strings.SplitN(v, "=", 2)

		if s.Queries == nil {
			s.Queries = make(map[string][]string)
		}

		s.Queries[parts[0]] = []string{parts[1]}

		return s
	})(s)
}

func AdminCookiesExtreme(s Shot) []Shot {
	values := []string{
		"is_admin=true",
		"is_admin=1",
		"is_admin=yes",
		"is_admin=on",

		"admin=true",
		"admin=1",
		"admin=yes",
		"admin=on",

		"administrator=true",
		"administrator=1",

		"isadmin=true",
		"isadmin=1",

		"isAdmin=true",
		"isAdmin=1",

		"IsAdmin=true",
		"IsAdmin=1",

		"IS_ADMIN=true",
		"IS_ADMIN=1",

		"admin_user=true",
		"admin_user=1",

		"adminuser=true",
		"adminuser=1",

		"user_is_admin=true",
		"user_is_admin=1",

		"user_isadmin=true",
		"user_isadmin=1",

		"user_role=admin",
		"role=admin",
		"role=administrator",
		"access_level=admin",
		"privilege=admin",
	}

	return vary(values, func(s Shot, v string) Shot {
		parts := strings.SplitN(v, "=", 2)

		if s.Cookies == nil {
			s.Cookies = make(map[string][]string)
		}

		s.Cookies[parts[0]] = []string{parts[1]}

		return s
	})(s)
}

func AdminQueriesExtreme(s Shot) []Shot {
	values := []string{
		"is_admin=true",
		"is_admin=1",
		"is_admin=yes",
		"is_admin=on",

		"admin=true",
		"admin=1",
		"admin=yes",
		"admin=on",

		"administrator=true",
		"administrator=1",

		"isadmin=true",
		"isadmin=1",

		"isAdmin=true",
		"isAdmin=1",

		"IsAdmin=true",
		"IsAdmin=1",

		"IS_ADMIN=true",
		"IS_ADMIN=1",

		"admin_user=true",
		"admin_user=1",

		"adminuser=true",
		"adminuser=1",

		"user_is_admin=true",
		"user_is_admin=1",

		"user_isadmin=true",
		"user_isadmin=1",

		"user_role=admin",
		"role=admin",
		"role=administrator",
		"access_level=admin",
		"privilege=admin",
	}

	return vary(values, func(s Shot, v string) Shot {
		parts := strings.SplitN(v, "=", 2)

		if s.Queries == nil {
			s.Queries = make(map[string][]string)
		}

		s.Queries[parts[0]] = []string{parts[1]}

		return s
	})(s)
}

func AdminHeadersExtreme(s Shot) []Shot {
	values := []string{
		"X-Admin=true",
		"X-Admin=1",
		"X-Admin=yes",
		"X-Admin=on",

		"X-Is-Admin=true",
		"X-Is-Admin=1",

		"X-Admin-User=true",
		"X-Admin-User=1",

		"X-Administrator=true",
		"X-Administrator=1",

		"X-User-Is-Admin=true",
		"X-User-Is-Admin=1",

		"X-User-Role=admin",
		"X-Role=admin",

		"X-Access-Level=admin",
		"X-Privilege=admin",

		"X-Authenticated=true",
		"X-Authenticated=1",

		"X-Auth-User=admin",
		"X-Forwarded-User=admin",
		"X-Remote-User=admin",
		"X-Original-User=admin",

		"X-User=admin",
		"X-Forwarded-Role=admin",
	}

	return vary(values, func(s Shot, v string) Shot {
		parts := strings.SplitN(v, "=", 2)

		s.Headers = cloneHeaders(s.Headers)
		s.Headers[parts[0]] = []string{parts[1]}

		return s
	})(s)
}
