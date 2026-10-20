package sidecar

import "testing"

func TestReviewSummaryDigestMatchesProtocol(t *testing.T) {
	summary := &ReviewSummary{Title: "Pay invoice", Fields: []ReviewSummaryField{
		{Label: "Amount", Value: "400"},
	}}
	digest, err := reviewSummaryDigest(summary)
	if err != nil || digest != "81736878d370aaf4e4c806fb828ce0e2cb3c9d1f550871b3648ba509ae8d9c22" {
		t.Fatalf("unexpected review digest %q: %v", digest, err)
	}
	summary.Title = "<script>"
	if _, err := reviewSummaryDigest(summary); err == nil {
		t.Fatal("unsafe review text was accepted")
	}
}

func TestReviewSummaryIsBoundToExecutorProof(t *testing.T) {
	syncer := decisionSynchronizer(t, nil)
	request := call(50)
	request.ReviewSummary = &ReviewSummary{Title: "Pay invoice", Fields: []ReviewSummaryField{
		{Label: "Amount", Value: "400"},
	}}
	signed := signedCall(t, syncer, request, "invoice-123")
	if err := syncer.verifyIdentityProof(signed, "invoice-123"); err != nil {
		t.Fatalf("signed review context rejected: %v", err)
	}
	signed.ReviewSummary.Fields[0].Value = "4000"
	if err := syncer.verifyIdentityProof(signed, "invoice-123"); err == nil {
		t.Fatal("changed review context was accepted")
	}
}
