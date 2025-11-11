package lksdk

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/livekit/protocol/livekit"
)

const (
	regionHostnameProviderSettingsCacheTime = 3 * time.Second
)

type regionURLProvider struct {
	hostnameSettingsCache map[string]*hostnameSettingsCacheItem // hostname -> regionSettings

	mutex      sync.RWMutex
	httpClient *http.Client
}

type hostnameSettingsCacheItem struct {
	regionSettings    *livekit.RegionSettings
	updatedAt         time.Time
	regionURLAttempts map[string]int
}

func newRegionURLProvider() *regionURLProvider {
	return &regionURLProvider{
		hostnameSettingsCache: make(map[string]*hostnameSettingsCacheItem),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					GetConfigForClient: getTLSConfigForClient,
				},
			},
		},
	}
}

// getTLSConfigForClient is called per TLS handshake to provide a dynamic tls.Config.
// It skips default verification but enforces it manually, appending cert details to errors.
func getTLSConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			hostname := hello.ServerName
			return verifyCertificates(hostname, rawCerts)
		},
	}, nil
}

// verifyCertificates manually verifies the provided cert chain against the system CA pool.
// On failure, it wraps the error with details like CA names (issuers) and SHA-256 fingerprints.
func verifyCertificates(hostname string, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("tls: no certificates provided in chain")
	}

	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("tls: failed to parse certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}

	// Load system roots for verification.
	roots := http.DefaultClient.Transport.(*http.Transport).TLSClientConfig.RootCAs

	// Verify the leaf cert (index 0) against roots, providing intermediates if present.
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		DNSName:       hostname,
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := certs[0].Verify(opts); err != nil {
		// Build diagnostic details.
		var details []string
		for i, cert := range certs {
			h := sha256.Sum256(rawCerts[i])
			fp := hex.EncodeToString(h[:])

			subj := cert.Subject.CommonName
			if len(cert.Subject.Organization) > 0 {
				subj = cert.Subject.Organization[0]
			}

			issuer := cert.Issuer.CommonName
			if len(cert.Issuer.Organization) > 0 {
				issuer = cert.Issuer.Organization[0]
			}

			details = append(details, fmt.Sprintf("  Cert %d: Subject=%q, Issuer=%q (CA), SHA256=%s", i, subj, issuer, fp))
		}
		return fmt.Errorf("tls: certificate verification failed for %s: %w\nChain details:\n%s", hostname, err, strings.Join(details, "\n"))
	}

	return nil
}

func (r *regionURLProvider) RefreshRegionSettings(cloudHostname, token string) error {
	r.mutex.RLock()
	hostnameSettings := r.hostnameSettingsCache[cloudHostname]
	r.mutex.RUnlock()

	if hostnameSettings != nil && time.Since(hostnameSettings.updatedAt) < regionHostnameProviderSettingsCacheTime {
		return nil
	}

	settingsURL := "https://" + cloudHostname + "/settings/regions"
	req, err := http.NewRequest("GET", settingsURL, nil)
	if err != nil {
		return errors.New("refreshRegionSettings failed to create request: " + err.Error())
	}
	req.Header = http.Header{
		"Authorization": []string{"Bearer " + token},
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err // Now includes enhanced TLS details if applicable.
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("refreshRegionSettings failed to fetch region settings. http status: " + resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("refreshRegionSettings failed to read response body: " + err.Error())
	}
	regions := &livekit.RegionSettings{}
	if err := protojson.Unmarshal(respBody, regions); err != nil {
		return errors.New("refreshRegionSettings failed to decode region settings: " + err.Error())
	}

	item := &hostnameSettingsCacheItem{
		regionSettings:    regions,
		updatedAt:         time.Now(),
		regionURLAttempts: map[string]int{},
	}
	r.mutex.Lock()
	r.hostnameSettingsCache[cloudHostname] = item
	r.mutex.Unlock()

	if len(item.regionSettings.Regions) == 0 {
		logger.Warnw("no regions returned", nil, "cloudHostname", cloudHostname)
	}

	return nil
}

// PopBestURL removes and returns the best region URL. Once all URLs are exhausted, it will return an error.
// RefreshRegionSettings must be called to repopulate the list of regions.
func (r *regionURLProvider) PopBestURL(cloudHostname, token string) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	hostnameSettings := r.hostnameSettingsCache[cloudHostname]

	if hostnameSettings == nil || hostnameSettings.regionSettings == nil || len(hostnameSettings.regionSettings.Regions) == 0 {
		return "", errors.New("no regions available")
	}

	bestRegionURL := hostnameSettings.regionSettings.Regions[0].Url
	hostnameSettings.regionSettings.Regions = hostnameSettings.regionSettings.Regions[1:]

	return bestRegionURL, nil
}

func parseCloudURL(serverURL string) (string, error) {
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server url (%s): %v", serverURL, err)
	}

	if !isCloud(parsedURL.Hostname()) {
		return "", errors.New("not a cloud url")
	}

	return parsedURL.Hostname(), nil
}

func isCloud(hostname string) bool {
	return strings.HasSuffix(hostname, "livekit.cloud") || strings.HasSuffix(hostname, "livekit.io")
}
