package nvd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/mmcdole/gofeed"
)

const (
	RSSFeed        = "https://nvd.nist.gov/download/nvd-rss-analyzed.xml"
	CVEURLBase     = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	NVDAPIEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	PageSize       = 2000 // maximum page size with the 2.0 API is 2000
	fileNameBase   = "nvdcve-1.1-"
	startingYear   = 2002
	CVEPathDefault = "cve_jsons"
	projectId      = "oss-vdb"
)

func LatestCVEsIDs() ([]string, error) {
	vulns, err := parseRSS()
	if err != nil {
		return nil, err
	}

	return vulns, nil
}

func parseRSS() ([]string, error) {
	fp := gofeed.NewParser()
	feed, err := fp.ParseURL(RSSFeed)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse RSS feed: %w", err)
	}

	vulns := []string{}

	for _, item := range feed.Items {
		u, err := url.Parse(item.Link)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse %s: %w", item.Link, err)
		}

		vuln := u.Query().Get("vulnId")
		if vuln == "" {
			log.Printf("No vulnId in %s", item.Link)
			continue
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

type NVDClient struct {
	httpClient *http.Client
	API        *url.URL
	Key        string
}

func NewNVDClient(APIKey string) (*NVDClient, error) {
	APIURL, err := url.Parse(NVDAPIEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse %s: %w", NVDAPIEndpoint, err)
	}

	client := http.DefaultClient

	return &NVDClient{
		httpClient: client,
		API:        APIURL,
		Key:        APIKey,
	}, nil
}

// Download one "page" of the CVE data using the 2.0 API
// Pages are offset based, this assumes the default (and maximum) page size of PageSize
// Maintaining the recommended 6 seconds betweens calls is left to the caller.
// See https://nvd.nist.gov/developers/vulnerabilities
func (c *NVDClient) CVEbyID(vulnID string) (*CVE, error) {

	APIURL := *c.API

	params := url.Values{}

	params.Add("cveId", vulnID)

	// if offset > 0 {
	// 	params.Add("startIndex", strconv.Itoa(offset))
	// }

	APIURL.RawQuery = params.Encode()

	log.Printf("Downloading %s", APIURL.String())

	req, err := http.NewRequest("GET", APIURL.String(), nil)
	if c.Key != "" {
		req.Header.Add("apiKey", c.Key)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to download %s: %w", APIURL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to download %s: %s", APIURL.String(), resp.Status)
	}

	var nvdResponse NVDResponse

	if err := json.NewDecoder(resp.Body).Decode(&nvdResponse); err != nil {
		return nil, fmt.Errorf("Failed to decode NVD data: %w", err)
	}

	if len(nvdResponse.Vulnerabilities) != 1 {
		return nil, fmt.Errorf("Expected 1 CVE, got %d", len(nvdResponse.Vulnerabilities))
	}

	return &nvdResponse.Vulnerabilities[0].CVE, nil
}
