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
	// Access vector
	AV_L = 0.395 // local access
	AV_A = 0.646 // adjacent network accessible
	AV_N = 1.0   // network accessible

	// Access complexity
	AC_H = 0.35 // high
	AC_M = 0.61 // medium
	AC_L = 0.71 // low

	// Authentication
	Au_M = 0.45  // multiple instances of authentication
	Au_S = 0.56  // single instance of authentication
	Au_N = 0.704 // no authentication

	// Confidentiality impact
	C_N = 0.0   // none
	C_P = 0.275 // partial
	C_C = 0.660 //complete

	// Integrity impact
	I_N = 0.0   // none
	I_P = 0.275 // partial
	I_C = 0.660 // complete

	// Avaliability impact
	A_N = 0.0   // none
	A_P = 0.275 // partial
	A_C = 0.660 // complete

)

// Metric is a simple struct that comprises all relevant vectors of a CVSS metric string
type BaseMetric struct {
	AccessVector     float64
	AccessComplexity float64
	Authentication   float64
	Confidentiality  float64
	Integrity        float64
	Avaliability     float64
}

// CalculateBaseScore parses the metric string in the required format.
// Currently only CVSS version 2 is supported.
// It returns the calculated CVSS base score and any error encountered.
func CalculateBaseScore(metric string, version int) (float64, error) {

	// At this time, ony version 2 is supported
	if version != 2 {
		return 0, errors.New("This CVSS version is not supported")
	}
	m, err := ParseBaseScore(metric)
	if err != nil {
		return 0, err
	}
	exploitability := 20 * m.AccessVector * m.AccessComplexity * m.Authentication
	impact := 10.41 * (1 - (1-m.Confidentiality)*(1-m.Integrity)*(1-m.Avaliability))
	f_i := 1.176
	if impact == 0 {
		f_i = 0
	}
	baseScore := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_i

	// Due to a lack of a round function, we need this clunky workaround..
	baseScore = math.Floor(baseScore*10+.5) / 10
	return baseScore, nil
}

// Parse splits the string into the appropriate metric groups.
// returns a metric struct and any error encountered.
func ParseBaseScore(metric string) (BaseMetric, error) {
	result := BaseMetric{}
	r := regexp.MustCompile(`AV:([LAN])/AC:([HML])/Au:([MSN])/C:([NPC])/I:([NPC])/A:([NPC])`)
	matches := r.FindAllStringSubmatch(metric, -1)
	if matches == nil {
		return result, errors.New("Could not parse metric string")

	}

	// Parse AV value
	switch matches[0][1] {
	case "L":
		result.AccessVector = AV_L
	case "A":
		result.AccessVector = AV_A
	case "N":
		result.AccessVector = AV_N
	}

	// Parse AC value
	switch matches[0][2] {
	case "H":
		result.AccessComplexity = AC_H
	case "L":
		result.AccessComplexity = AC_L
	case "M":
		result.AccessComplexity = AC_M
	}

	// Parse Au value
	switch matches[0][3] {
	case "M":
		result.Authentication = Au_M
	case "S":
		result.Authentication = Au_S
	case "N":
		result.Authentication = Au_N
	}

	// Parse C value
	switch matches[0][4] {
	case "N":
		result.Confidentiality = C_N
	case "P":
		result.Confidentiality = C_P
	case "C":
		result.Confidentiality = C_C
	}

	// Parse I value
	switch matches[0][5] {
	case "N":
		result.Integrity = I_N
	case "P":
		result.Integrity = I_P
	case "C":
		result.Integrity = I_C
	}

	// Parse A value
	switch matches[0][6] {
	case "N":
		result.Avaliability = A_N
	case "P":
		result.Avaliability = A_P
	case "C":
		result.Avaliability = A_C
	}

	return result, nil

}
