package fuzz

type FuzzFunc func(Shot) []Shot
type FuncType int

const (
	FuncTypeAnd FuncType = iota
	FuncTypeOr
)

type FuzzFunction struct {
	Func FuzzFunc
	Type FuncType
}

type Fuzz struct {
	base  *Shot
	funcs []FuzzFunction
}

func NewFuzzer(base *Shot) *Fuzz {
	return &Fuzz{
		base:  base,
		funcs: make([]FuzzFunction, 0),
	}
}

func (fz *Fuzz) shot() *Shot {
	if fz.base == nil {
		fz.base = &Shot{}
	}
	return fz.base
}

func (fz *Fuzz) Uri(uri string) *Fuzz {
	fz.shot().Uri = uri
	return fz
}

func (fz *Fuzz) Method(method string) *Fuzz {
	fz.shot().Method = method
	return fz
}

func (fz *Fuzz) DomainName(domain string) *Fuzz {
	fz.shot().DomainName = domain
	return fz
}

func (fz *Fuzz) Body(body string) *Fuzz {
	fz.shot().BodyRaw = body
	return fz
}

func (fz *Fuzz) Https(https bool) *Fuzz {
	fz.shot().Https = https
	return fz
}

func (fz *Fuzz) Cookie(key, value string) *Fuzz {
	shot := fz.shot()
	if shot.Cookies == nil {
		shot.Cookies = make(map[string][]string)
	}
	shot.Cookies[key] = append(shot.Cookies[key], value)
	return fz
}

func (fz *Fuzz) Header(key, value string) *Fuzz {
	shot := fz.shot()
	if shot.Headers == nil {
		shot.Headers = make(map[string][]string)
	}
	shot.Headers[key] = append(shot.Headers[key], value)
	return fz
}

func (fz *Fuzz) Queries(key, value string) *Fuzz {
	shot := fz.shot()
	if shot.Queries == nil {
		shot.Queries = make(map[string][]string)
	}
	shot.Queries[key] = append(shot.Queries[key], value)
	return fz
}

func (fz *Fuzz) AndFunc(f FuzzFunc) {
	fz.funcs = append(fz.funcs, FuzzFunction{Func: f, Type: FuncTypeAnd})
}

func (fz *Fuzz) OrFunc(f FuzzFunc) {
	fz.funcs = append(fz.funcs, FuzzFunction{Func: f, Type: FuncTypeOr})
}

func (fz *Fuzz) ChainFunc(fxs ...FuzzFunc) {
	f := func(base Shot) []Shot {
		results := make([]Shot, 0)
		for _, fx := range fxs {
			b := base.Clone()
			results = append(results, fx(b)...)
		}

		return results
	}
	fz.funcs = append(fz.funcs, FuzzFunction{Func: f, Type: FuncTypeAnd})

}

type result struct {
	shots []Shot
}

func (fz *Fuzz) fuzz(index int, base Shot, r *result) {
	if index >= len(fz.funcs) {
		r.shots = append(r.shots, base)
		return
	}

	if fz.funcs[index].Type == FuncTypeOr {
		fz.fuzz(index+1, base, r)
	}
	shots := fz.funcs[index].Func(base)
	for _, shot := range shots {
		fz.fuzz(index+1, shot.Clone(), r)
	}
}

func (fz *Fuzz) calcSize() int {
	size := 1
	base := fz.base
	for _, f := range fz.funcs {
		var variationSize int
		variationSize = len(f.Func(*base))

		if f.Type == FuncTypeOr {
			variationSize++
		}
		size *= variationSize
	}
	return size
}

func (fz *Fuzz) Fuzz() []Shot {
	size := fz.calcSize()
	shots := make([]Shot, 0, size)
	result := result{shots: shots}
	fz.fuzz(0, *fz.base, &result)
	return result.shots
}
