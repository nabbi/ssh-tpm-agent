package askpass

import (
	"bytes"
	"os"
	"testing"
)

func withoutPromptEnv(t *testing.T, stdin *os.File) {
	t.Helper()
	for _, v := range []string{"DISPLAY", "WAYLAND_DISPLAY", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"} {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
	old := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = old })
}

// A daemon without a display, without SSH_ASKPASS and with stdin not a
// terminal has nowhere to prompt. It must report that as an error rather
// than return an empty passphrase, which the agent would otherwise send to
// the TPM and count towards the dictionary attack lockout.
func TestReadPassphraseNoTerminalIsError(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	withoutPromptEnv(t, devnull)

	pin, err := ReadPassphrase("Enter passphrase: ", RP_USE_ASKPASS)
	if err == nil {
		t.Fatalf("expected an error, got passphrase %q", pin)
	}
	if len(pin) != 0 {
		t.Fatalf("expected no passphrase on error, got %q", pin)
	}
}

// Interactive tools that allow stdin (ssh-tpm-keygen) keep reading the
// passphrase from a non-terminal stdin, one line per prompt.
func TestReadPassphraseAllowStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	withoutPromptEnv(t, r)
	if _, err := w.WriteString("first\r\nsecond\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	for _, want := range []string{"first", "second", ""} {
		pin, err := ReadPassphrase("Enter passphrase: ", RP_ALLOW_STDIN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(pin, []byte(want)) {
			t.Fatalf("expected %q, got %q", want, pin)
		}
	}
}
