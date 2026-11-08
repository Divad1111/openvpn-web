package policy

import "testing"

func TestWriteEnabledFailsClosed(t *testing.T) {
	for _, c := range []struct {
		input string
		want  bool
	}{
		{"true", true}, {"", false}, {"TRUE", false}, {"True", false},
		{"1", false}, {"yes", false}, {"false", false}, {" true", false},
		{"true ", false}, {"true\n", false},
	} {
		if got := WriteEnabled(c.input); got != c.want {
			t.Errorf("%q: got %v, want %v", c.input, got, c.want)
		}
	}
}
func TestEffectiveWriteMode(t *testing.T) {
	for _, c := range []struct{ m, a, want bool }{
		{false, false, false}, {true, false, false}, {false, true, false}, {true, true, true},
	} {
		if got := EffectiveWriteMode(c.m, c.a); got != c.want {
			t.Fatalf("manager=%v agent=%v got=%v", c.m, c.a, got)
		}
	}
}
