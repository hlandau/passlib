package passlib

import "testing"

func TestPasslib(t *testing.T) {
	h, err := Hash("password")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	newHash, err := Verify("password", h)
	if err != nil {
		t.Fatalf("err verifying: %v (%#v)", err, h)
	}
	if newHash != "" {
		t.Fatalf("non-empty newHash with hash just created")
	}

	newHash, err = Verify("password2", h)
	if err == nil {
		t.Fatalf("got nil error with wrong password")
	}
	if newHash != "" {
		t.Fatalf("non-empty newHash with wrong password")
	}
}

// © 2014 Hugo Landau <hlandau@devever.net>  BSD License
