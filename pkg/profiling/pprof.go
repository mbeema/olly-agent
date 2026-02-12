// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build linux

package profiling

import (
	"bytes"
	"time"

	pprofProfile "github.com/google/pprof/profile"
)

// buildPProf constructs a gzip-compressed pprof protobuf from aggregated stack samples.
func buildPProf(pid uint32, stacks map[stackKey]uint64, frames map[stackKey][]uint64,
	resolver *symbolResolver, start, end time.Time) ([]byte, error) {

	prof := &pprofProfile.Profile{
		SampleType: []*pprofProfile.ValueType{
			{Type: "cpu", Unit: "nanoseconds"},
		},
		TimeNanos:     start.UnixNano(),
		DurationNanos: end.Sub(start).Nanoseconds(),
	}

	// Track unique locations and functions to avoid duplicates
	locationMap := make(map[uint64]*pprofProfile.Location) // addr → Location
	functionMap := make(map[string]*pprofProfile.Function) // funcName → Function
	var locID, funcID uint64

	for key, count := range stacks {
		ips, ok := frames[key]
		if !ok {
			continue
		}

		var locations []*pprofProfile.Location
		for _, ip := range ips {
			if ip == 0 {
				break
			}

			loc, exists := locationMap[ip]
			if !exists {
				locID++
				funcName := resolver.Resolve(pid, ip)

				fn, fnExists := functionMap[funcName]
				if !fnExists {
					funcID++
					fn = &pprofProfile.Function{
						ID:   funcID,
						Name: funcName,
					}
					functionMap[funcName] = fn
					prof.Function = append(prof.Function, fn)
				}

				loc = &pprofProfile.Location{
					ID:      locID,
					Address: ip,
					Line: []pprofProfile.Line{
						{Function: fn},
					},
				}
				locationMap[ip] = loc
				prof.Location = append(prof.Location, loc)
			}

			locations = append(locations, loc)
		}

		if len(locations) > 0 {
			// Value is sample count * interval (approximate nanoseconds per sample)
			intervalNs := end.Sub(start).Nanoseconds()
			totalSamples := uint64(0)
			for _, c := range stacks {
				totalSamples += c
			}
			valueNs := int64(count)
			if totalSamples > 0 {
				valueNs = int64(float64(count) / float64(totalSamples) * float64(intervalNs))
			}

			prof.Sample = append(prof.Sample, &pprofProfile.Sample{
				Location: locations,
				Value:    []int64{valueNs},
			})
		}
	}

	if len(prof.Sample) == 0 {
		return nil, nil
	}

	// prof.Write() outputs gzip-compressed protobuf (pprof standard format)
	var buf bytes.Buffer
	if err := prof.Write(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
