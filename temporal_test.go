package cvss

import "testing"

func TestTemporalParse(t *testing.T) {
	m := TemporalMetric{Exploitability: 0.85, RemediationLevel: 0.95, ReportConfidence: 0.9}
	cvssString := `E:U/RL:W/RC:UC`

	metric, err := ParseTemporalScore(cvssString)
	if err != nil {
		t.Errorf("Could not parse %s: %s", cvssString, err)
	}
	if metric != m {
		t.Errorf("Could not parse %s: Expected %+v, got %+v", cvssString, m, metric)
	}
}

func TestCalculateTemporalScore(t *testing.T) {
	cvssString := `E:F/RL:OF/RC:C`
	score, err := CalculateTemporalScore(cvssString, 7.8, 3)
	if err == nil {
		t.Error("Version 3 should not be supported yet")
	}
	score, err = CalculateTemporalScore(cvssString, 7.8, 2)
	if err != nil {
		t.Error(err)
	}
	if score != 6.4 {
		t.Errorf("Expected 7.8 BaseScore, got %f", score)
	}

}
