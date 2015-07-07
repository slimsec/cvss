// Copyright 2015 by Daniel Hauenstein, SlimSec IT GmbH. All rights reserved.

// Package cvss provides functions to calculate the CVSS base score from a metric string
// The function used to calculated the CVSS base score can be found at https://www.first.org/cvss/v2/guide
package cvss

import (
	"errors"
	"math"
	"regexp"
)

const (
	// Exploitability vector
	E_U   = 0.85 // unproven
	E_POC = 0.9  // proof of concept
	E_F   = 0.95 // functional
	E_H   = 1.00 // high
	E_ND  = 1.00 // not defined

	// RemidiationLevel vector

	RL_OF = 0.87 // official fix
	RL_TF = 0.90 // temporary-fix
	RL_W  = 0.95 // workaround
	RL_U  = 1.00 // unavailable
	RL_ND = 1.00 // not defined

	// ReportConfidence vector

	RC_UC = 0.90 // unconfirmed
	RC_UR = 0.95 // uncorroborated
	RC_C  = 1.00 // confirmed
	RC_ND = 1.00 // not defined
)

// TemporalMetric is a simple struct that comprises all relevant vectors of a CVSS temporal metric string
type TemporalMetric struct {
	Exploitability   float64
	RemediationLevel float64
	ReportConfidence float64
}

// CalculateTemporalScore parses the metric string in the required format and accepts a base metric score.
// Currently only CVSS version 2 is supported.
// It returns the calculated CVSS temporal score and any error encountered.
func CalculateTemporalScore(metric string, basescore float64, version int) (float64, error) {

	// At this time, ony version 2 is supported
	if version != 2 {
		return 0, errors.New("This CVSS version is not supported")
	}
	m, err := ParseTemporalMetric(metric)
	if err != nil {
		return 0, err
	}
	// Due to a lack of a round function, we need this clunky workaround..
	temporalScore := math.Floor(m.Exploitability*m.RemediationLevel*m.ReportConfidence*basescore*10+.5) / 10
	return temporalScore, nil
}

// ParseTemporalMetric splits the string into the appropriate metric groups.
// returns a metric struct and any error encountered.
func ParseTemporalMetric(metric string) (TemporalMetric, error) {
	result := TemporalMetric{}
	r := regexp.MustCompile(`E:(POC|ND|[UFH])/RL:(OF|TF|ND|[WU])/RC:(UC|UR|ND|C)`)
	matches := r.FindAllStringSubmatch(metric, -1)
	if matches == nil {
		return result, errors.New("Could not parse metric string")

	}

	// Parse E value
	switch matches[0][1] {
	case "U":
		result.Exploitability = E_U
	case "POC":
		result.Exploitability = E_POC
	case "F":
		result.Exploitability = E_F
	case "H":
		result.Exploitability = E_H
	case "ND":
		result.Exploitability = E_ND
	}

	// Parse RL value
	switch matches[0][2] {
	case "OF":
		result.RemediationLevel = RL_OF
	case "TF":
		result.RemediationLevel = RL_TF
	case "W":
		result.RemediationLevel = RL_W
	case "U":
		result.RemediationLevel = RL_U
	case "ND":
		result.RemediationLevel = RL_ND
	}

	// Parse RC value
	switch matches[0][3] {
	case "UC":
		result.ReportConfidence = RC_UC
	case "UR":
		result.ReportConfidence = RC_UR
	case "C":
		result.ReportConfidence = RC_C
	case "ND":
		result.ReportConfidence = RC_ND
	}
	return result, nil

}
