package ca

import (
	"errors"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandHomeWithEnvHOME(t *testing.T) {
	t.Setenv("HOME", "/tmp/gomitm-home")

	got, err := expandHome("~/.gomitm/ca")
	if err != nil {
		t.Fatalf("expandHome failed: %v", err)
	}
	want := filepath.Join("/tmp/gomitm-home", ".gomitm", "ca")
	if got != want {
		t.Fatalf("expandHome got=%q want=%q", got, want)
	}
}

func TestExpandHomeFallbackToUserLookup(t *testing.T) {
	t.Setenv("HOME", "")

	oldCurrent := lookupCurrentUser
	oldLookupID := lookupUserByID
	oldUID := currentUID
	t.Cleanup(func() {
		lookupCurrentUser = oldCurrent
		lookupUserByID = oldLookupID
		currentUID = oldUID
	})

	lookupCurrentUser = func() (*user.User, error) {
		return nil, errors.New("current user not available")
	}
	currentUID = func() int { return 1001 }
	lookupUserByID = func(uid string) (*user.User, error) {
		if uid != "1001" {
			t.Fatalf("unexpected uid: %s", uid)
		}
		return &user.User{Uid: uid, HomeDir: "/var/lib/gomitm"}, nil
	}

	got, err := expandHome("~/data")
	if err != nil {
		t.Fatalf("expandHome failed: %v", err)
	}
	want := filepath.Join("/var/lib/gomitm", "data")
	if got != want {
		t.Fatalf("expandHome got=%q want=%q", got, want)
	}
}

func TestExpandHomeErrorWhenNoSource(t *testing.T) {
	t.Setenv("HOME", "")

	oldCurrent := lookupCurrentUser
	oldLookupID := lookupUserByID
	oldUID := currentUID
	t.Cleanup(func() {
		lookupCurrentUser = oldCurrent
		lookupUserByID = oldLookupID
		currentUID = oldUID
	})

	lookupCurrentUser = func() (*user.User, error) {
		return nil, errors.New("no current user")
	}
	currentUID = func() int { return 9999 }
	lookupUserByID = func(uid string) (*user.User, error) {
		return nil, errors.New("lookup failed")
	}

	_, err := expandHome("~/data")
	if err == nil {
		t.Fatal("expected expandHome error")
	}
	if !strings.Contains(err.Error(), "get home dir") {
		t.Fatalf("unexpected error: %v", err)
	}
}
