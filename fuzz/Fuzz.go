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

func (fz *Fuzz) AndFunc(f FuzzFunc) {
	fz.funcs = append(fz.funcs, FuzzFunction{Func: f, Type: FuncTypeAnd})
}

func (fz *Fuzz) OrFunc(f FuzzFunc) {
	fz.funcs = append(fz.funcs, FuzzFunction{Func: f, Type: FuncTypeOr})
}

type Result struct {
	shots []Shot
}

func (fz *Fuzz) fuzz(index int, base Shot, r *Result) {
	if index >= len(fz.funcs) {
		r.shots = append(r.shots, base)
		return
	}

	if fz.funcs[index].Type == FuncTypeOr {
		fz.fuzz(index, base, r)
	}
	shots := fz.funcs[index].Func(base)
	for _, shot := range shots {
		fz.fuzz(index+1, shot, r)
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
	result := Result{shots: shots}
	fz.fuzz(0, *fz.base, &result)
	return result.shots
}
