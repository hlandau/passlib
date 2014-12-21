package passlib

import "testing"

func TestPasslib(t *testing.T) {
  h, err := Hash("password")
  if err != nil {
    t.Fatalf("err: %v", err)
  }

  _, err = Verify("password", h)
  if err != nil {
    t.Fatalf("err verifying: %v (%#v)", err, h)
  }

  _, err = Verify("password2", h)
  if err == nil {
    t.Fatalf("got nil error with wrong password")
  }
}
