package shareproxy

import (
	"strings"
	"testing"
)

const signinChunk = "import{a as b}from\"./x.js\";var L=s({__name:`SigninView`,setup(t){let n=M(),r=A();return()=>1}});export{L as default};"

func TestPatchSigninView(t *testing.T) {
	out, ok := patchSigninView([]byte(signinChunk))
	if !ok {
		t.Fatal("patch did not apply")
	}
	got := string(out)
	want := "__name:`SigninView`,setup(t){" + signinRedirect + "let n=M()"
	if !strings.Contains(got, want) {
		t.Fatalf("redirect not injected at the start of setup:\n%s", got)
	}
	if !strings.Contains(got, `location.replace("/signin?ad=1"`) || !strings.Contains(got, "ad=1(&|$)") {
		t.Fatal("redirect lost its loop guard")
	}

	// idempotent: a chunk that is already patched is reported as applied and left alone
	again, ok := patchSigninView(out)
	if !ok || string(again) != got {
		t.Fatal("patching twice changed the chunk")
	}
}

func TestPatchSigninViewUnknownChunk(t *testing.T) {
	in := []byte("var x=1;export{x as default}")
	out, ok := patchSigninView(in)
	if ok || string(out) != string(in) {
		t.Fatal("an unrelated chunk must pass through untouched and report not applied")
	}
}
