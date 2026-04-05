package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("cert or key is nil")
	}
	if !cert.IsCA {
		t.Error("cert is not a CA")
	}
	if cert.Subject.CommonName != "Kumo CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Kumo CA")
	}

	// Files should exist
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Errorf("ca.pem not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-key.pem")); err != nil {
		t.Errorf("ca-key.pem not created: %v", err)
	}

	// ca-key.pem should be 0600
	info, _ := os.Stat(filepath.Join(dir, "ca-key.pem"))
	if info.Mode().Perm() != 0600 {
		t.Errorf("ca-key.pem mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadCA(t *testing.T) {
	dir := t.TempDir()
	orig, origKey, _ := GenerateCA(dir)

	loaded, loadedKey, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if loaded.SerialNumber.Cmp(orig.SerialNumber) != 0 {
		t.Error("loaded cert serial doesn't match original")
	}
	if !loadedKey.Equal(origKey) {
		t.Error("loaded key doesn't match original")
	}
}

func TestLoadCA_Missing(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadCA(dir)
	if err == nil {
		t.Error("expected error for missing CA")
	}
}

func TestLoadOrGenerateCA(t *testing.T) {
	dir := t.TempDir()

	// First call generates
	cert1, _, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call loads same cert
	cert2, _, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if cert1.SerialNumber.Cmp(cert2.SerialNumber) != 0 {
		t.Error("second call returned different cert")
	}
}
