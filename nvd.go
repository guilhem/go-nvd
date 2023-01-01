package nvd

import (
	"encoding/json"
	"time"
)

type CVETime time.Time

type CVE struct {
	ID               string        `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published        CVETime       `json:"published"`
	LastModified     CVETime       `json:"lastModified"`
	VulnStatus       string        `json:"vulnStatus"`
	Descriptions     []Description `json:"descriptions"`
	Metrics          struct {
		CvssMetricV2 []struct {
			Source   string `json:"source"`
			Type     string `json:"type"`
			CvssData struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssData"`
			BaseSeverity            string  `json:"baseSeverity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			AcInsufInfo             bool    `json:"acInsufInfo"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Source      string `json:"source"`
		Type        string `json:"type"`
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			Operator string `json:"operator"`
			Negate   bool   `json:"negate"`
			CpeMatch []struct {
				Vulnerable      bool   `json:"vulnerable"`
				Criteria        string `json:"criteria"`
				MatchCriteriaID string `json:"matchCriteriaId"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL    string `json:"url"`
		Source string `json:"source"`
	} `json:"references"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func (c *CVE) Vulnerable(vendor, product string) bool {
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, cpe := range node.CpeMatch {
				if cpe.Criteria == "cpe:2.3:a:"+vendor+":"+product+":*" {
					return cpe.Vulnerable
				}
			}
		}
	}

	return false
}

const CVETimeFormat = "2006-01-02T15:04:05.000"

func (t *CVETime) UnmarshalJSON(data []byte) error {
	// Parse the time string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsedTime, err := time.Parse(CVETimeFormat, s)
	if err != nil {
		return err
	}

	// Set the time value
	*t = CVETime(parsedTime)
	return nil
}

func (t CVETime) MarshalJSON() ([]byte, error) {
	// Format the time as a string
	s := time.Time(t).Format("2006-01-02T15:04:05.000")

	// Marshal the string as JSON
	return json.Marshal(s)
}

// type CVETime time.Time

// func (c *CVETime) UnmarshalJSON(b []byte) error {
// 	var val string

// 	if err := json.Unmarshal(b, &val); err != nil {
// 		return err
// 	}

// 	t, err := time.Parse(time.RFC3339, val)
// 	if err != nil {
// 		return err
// 	}

// 	*c = CVETime(t) //set result using the pointer

// 	return nil
// }

// func (c CVETime) MarshalJSON() ([]byte, error) {
// 	return json.Marshal(time.Time(c).Format(time.RFC3339))
// }

// type CVEtimestamp time.Time

// func (c *CVEtimestamp) UnmarshalJSON(b []byte) error {
// 	var val string

// 	if err := json.Unmarshal(b, &val); err != nil {
// 		return err
// 	}

// 	t, err := time.Parse(CVETimeFormat, val)
// 	if err != nil {
// 		return err
// 	}

// 	*c = CVEtimestamp(t) //set result using the pointer

// 	return nil
// }

// func (c CVEtimestamp) MarshalJSON() ([]byte, error) {
// 	return json.Marshal(time.Time(c).Format(CVETimeFormat))
// }

type NVDResponse struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Format          string            `json:"format"`
	Version         string            `json:"version"`
	Timestamp       string            `json:"timestamp"`
	Vulnerabilities []Vulnerabilities `json:"vulnerabilities"`
}

type Vulnerabilities struct {
	CVE CVE `json:"cve"`
}
