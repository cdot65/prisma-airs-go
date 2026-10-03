//go:build integration

package agentguard

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/agentguard/schema"
	"github.com/cdot65/prisma-airs-go/aisec/internal/testutil"
)

// TestIntegration_ArchiveScan is opt-in: it submits the exact bytes of a local
// ZIP without opening/extracting entries. Existing scans can be resumed with
// PANW_AGENT_GUARD_TEST_SCAN_UUID to avoid submitting the archive a second time.
// The service has no scan delete operation, so submitted records are retained.
func TestIntegration_ArchiveScan(t *testing.T) {
	testutil.LoadProjectEnv(t)
	archivePath := os.Getenv("PANW_AGENT_GUARD_TEST_ARCHIVE")
	scanUUID := os.Getenv("PANW_AGENT_GUARD_TEST_SCAN_UUID")
	if archivePath == "" && scanUUID == "" {
		t.Skip("set PANW_AGENT_GUARD_TEST_ARCHIVE to submit a ZIP, or PANW_AGENT_GUARD_TEST_SCAN_UUID to resume")
	}
	client, err := NewClient(Opts{HTTPClient: &http.Client{Timeout: time.Minute}, NumRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if scanUUID == "" {
		file, err := os.Open(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Error(err)
			}
		})
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		var magic [4]byte
		if _, err := file.ReadAt(magic[:], 0); err != nil || magic != [4]byte{'P', 'K', 3, 4} {
			t.Fatal("fixture must be a nonempty ZIP archive")
		}
		crc, digest := crc32.New(crc32.MakeTable(crc32.Castagnoli)), sha256.New()
		if _, err := io.Copy(io.MultiWriter(crc, digest), file); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		var checksum [4]byte
		binary.BigEndian.PutUint32(checksum[:], crc.Sum32())
		encodedCRC := base64.StdEncoding.EncodeToString(checksum[:])
		reservation, err := client.Scans.UploadURL(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !aisec.IsValidUUID(reservation.ScanUUID) {
			t.Fatal("invalid reserved scan UUID")
		}
		scanUUID = reservation.ScanUUID
		u, err := url.Parse(reservation.UploadURL)
		if err != nil || u.Scheme != "https" || !(u.Hostname() == "storage.googleapis.com" || strings.HasSuffix(u.Hostname(), ".storage.googleapis.com")) {
			t.Fatal("expected HTTPS Google Cloud Storage signed URL")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, reservation.UploadURL, io.NopCloser(file))
		if err != nil {
			t.Fatal("could not construct signed upload request (URL redacted)")
		}
		req.ContentLength = info.Size()
		req.Header.Set("Content-Type", "application/zip")
		// Only content-type and host are signed. In particular, an unsigned
		// x-goog-hash header is rejected as MalformedSecurityHeader.
		storage := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := storage.Do(req)
		if err != nil {
			t.Fatal("signed storage upload failed (URL redacted)")
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("signed upload HTTP %d", resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("X-Goog-Hash"), "crc32c="+encodedCRC) {
			t.Fatal("storage checksum does not match original archive")
		}
		t.Logf("Uploaded %d opaque ZIP bytes, sha256=%x, scan=%s", info.Size(), digest.Sum(nil), scanUUID)
		started, err := client.Scans.UploadComplete(ctx, scanUUID, schema.AgentGuardUploadCompleteRequest{
			Name: fmt.Sprintf("go-sdk-e2e-%d", time.Now().UnixNano()), ChecksumCrc32c: aisec.Value(encodedCRC),
		}, UploadCompleteOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if started.UUID != scanUUID {
			t.Fatal("upload completion returned a different scan")
		}
	}
	var completed *schema.AgentGuardScanResponse
	for completed == nil {
		scan, err := client.Scans.Get(ctx, scanUUID)
		if err != nil {
			t.Fatal(err)
		}
		if scan.UUID != scanUUID {
			t.Fatal("read returned a different scan")
		}
		t.Logf("Scan %s status=%s", scan.UUID, scan.Status)
		switch scan.Status {
		case schema.AgentGuardScanStatusCompleted:
			completed = scan
		case schema.AgentGuardScanStatusFailed, schema.AgentGuardScanStatusError:
			t.Fatalf("scan ended with status %s", scan.Status)
		default:
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(5 * time.Second):
			}
		}
	}
	findings, err := client.Scans.ListVulnerabilities(ctx, scanUUID, VulnerabilityListOpts{ListOpts: ListOpts{Limit: 500}})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings.Vulnerabilities {
		if finding.ScanUUID != scanUUID {
			t.Error("finding belongs to a different scan")
		}
	}
	chains, err := client.Scans.ListAttackChains(ctx, scanUUID, ListOpts{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range chains.AttackChains {
		if chain.ScanUUID != scanUUID {
			t.Error("attack chain belongs to a different scan")
		}
	}
	if len(chains.AttackChains) > 0 {
		detail, err := client.Scans.GetAttackChain(ctx, scanUUID, chains.AttackChains[0].UUID)
		if err != nil {
			t.Fatal(err)
		}
		if detail.UUID != chains.AttackChains[0].UUID || detail.ScanUUID != scanUUID {
			t.Error("attack chain detail identifiers differ")
		}
	}
	outcome, _ := completed.EvalOutcome.Get()
	t.Logf("Completed: policy=%s returned_findings=%d returned_attack_chains=%d", outcome, len(findings.Vulnerabilities), len(chains.AttackChains))
}
