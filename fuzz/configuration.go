package fuzz

func ApplyConfigurations(cfgs []Configuration) FuzzFunc {
	return func(s Shot) []Shot {
		shots := make([]Shot, 0, len(cfgs))
		for _, cfg := range cfgs {
			base := s.Clone()
			configured := cfg.Shot(base)
			shots = append(shots, configured)
		}

		return shots
	}
}
