package finder

import (
	"math/rand/v2"
	"strconv"

	"github.com/0FL01/WarpPocket/internal/model"
)

// Fixed pools from Viktor45/ros-scripts warp-finder.rsc, commit
// d92d68db030e833c7f6032697e4f177dfe976230 (MIT; notice embedded in the app).
var prefixes = [...]string{"8.6.112.", "8.34.70.", "8.34.146.", "8.35.211.", "8.39.125.", "8.39.204.", "8.39.214.", "8.47.69.", "162.159.192.", "162.159.193.", "162.159.195.", "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99."}
var ports = [...]int{500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886}

// Candidates never enumerates the cartesian product or exceeds thirty entries.
// A non-nil explicit slice replaces sampling, including an empty slice.
func (f *Finder) Candidates(p model.Profile, cache model.Cache, explicit []model.Endpoint, limit int) ([]model.Endpoint, error) {
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 1 {
		return nil, argumentsError()
	}
	if limit > DefaultLimit {
		limit = DefaultLimit
	}
	ordered := explicit
	if explicit == nil {
		ordered = make([]model.Endpoint, 0, 24)
		for _, r := range []*model.CheckResult{cache.Preferred, cache.LastGood} {
			if r != nil {
				ordered = append(ordered, r.Endpoint)
			}
		}
		for _, r := range cache.Fallbacks {
			ordered = append(ordered, r.Endpoint)
		}
		ordered = append(ordered, p.Endpoint)
		for _, prefix := range []string{"162.159.192.", "162.159.193.", "162.159.195."} {
			for _, port := range []int{2408, 500, 4500} {
				ordered = append(ordered, model.Endpoint{Host: prefix + "1", Port: port})
			}
		}
		for _, prefix := range prefixes[len(prefixes)-4:] {
			for _, port := range []int{4500, 2408} {
				ordered = append(ordered, model.Endpoint{Host: prefix + "1", Port: port})
			}
		}
	}
	seen := make(map[model.Endpoint]bool)
	result := make([]model.Endpoint, 0, limit)
	add := func(endpoint model.Endpoint) error {
		canonical, err := model.NewEndpoint(endpoint.Host, endpoint.Port)
		if err != nil {
			return err
		}
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
		return nil
	}
	for _, endpoint := range ordered {
		if err := add(endpoint); err != nil {
			return nil, err
		}
		if len(result) == limit {
			return result, nil
		}
	}
	if explicit == nil {
		for attempt := 0; attempt < limit*40 && len(result) < limit; attempt++ {
			_ = add(model.Endpoint{Host: prefixes[rand.IntN(len(prefixes))] + strconv.Itoa(2+rand.IntN(253)), Port: ports[rand.IntN(len(ports))]})
		}
	}
	return result, nil
}
