package cvss

import "testing"

func TestBaseParse(t *testing.T) {
	m := BaseMetric{AccessVector: 1, AccessComplexity: 0.71, Authentication: 0.704, Confidentiality: 0.0, Integrity: 0.0, Avaliability: 0.66}
	cvssString := `AV:N/AC:L/Au:N/C:N/I:N/A:C`

	metric, err := ParseBaseMetric(cvssString)
	if err != nil {
		t.Errorf("Could not parse %s: %s", cvssString, err)
	}
	if metric != m {
		t.Errorf("Could not parse %s: Expected %+v, got %+v", cvssString, m, metric)
	}
}
func TestCalculateBaseScore(t *testing.T) {
	cvssString := `AV:N/AC:L/Au:N/C:N/I:N/A:C`
	score, err := CalculateBaseScore(cvssString, 3)
	if err == nil {
		t.Error("Version 3 should not be supported yet")
	}
	score, err = CalculateBaseScore(cvssString, 2)
	if err != nil {
		t.Error(err)
	}
	if score != 7.8 {
		t.Errorf("Expected 7.8 BaseScore, got %f", score)
	}

}
