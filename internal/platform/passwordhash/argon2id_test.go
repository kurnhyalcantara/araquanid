package passwordhash

import "testing"

func testParams() Argon2idParams {
	// Deliberately cheap parameters so the test suite stays fast; production
	// values come from config.Auth.Argon2id (FR-PWD-004: t=3, m=65536, p=4).
	return Argon2idParams{TimeCost: 1, MemoryKB: 8 * 1024, Parallelism: 1}
}

func TestHashAndVerify(t *testing.T) {
	p := testParams()
	hash, salt, err := Hash("correct-horse-battery-staple", p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if hash == "" || salt == "" {
		t.Fatal("expected non-empty hash and salt")
	}

	if !Verify("correct-horse-battery-staple", hash, salt, p) {
		t.Error("Verify should succeed for the correct password")
	}
	if Verify("wrong-password", hash, salt, p) {
		t.Error("Verify should fail for the wrong password")
	}
}

func TestHashProducesDistinctSalts(t *testing.T) {
	p := testParams()
	_, salt1, err := Hash("same-password", p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	_, salt2, err := Hash("same-password", p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if salt1 == salt2 {
		t.Error("expected a fresh random salt on every Hash call")
	}
}

func TestVerifyRejectsMalformedInput(t *testing.T) {
	p := testParams()
	if Verify("x", "not-base64!!!", "also-not-base64!!!", p) {
		t.Error("Verify should fail closed on malformed hash/salt input")
	}
}

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	// DummyVerify's only contract is "costs the same as a real Verify and
	// never gates access" -- it has no return value to assert on.
	DummyVerify("anything", testParams())
}
