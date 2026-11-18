package policy

import (
	"reflect"
	"testing"
)

func TestCanonicalNetworks(t *testing.T) {
	got, err := Parse([]string{
		"::ffff:192.0.2.1/128",
		"10.0.1.0/24",
		"2001:db8::/48",
		"10.0.0.0/24",
		"10.0.1.1/32",
		"2001:db8:0:3::/64",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/23", "::ffff:c000:201/128", "2001:db8::/48"}
	if !reflect.DeepEqual(Strings(got), want) {
		t.Fatalf("canonical networks %v, want %v", Strings(got), want)
	}
}

func TestCanonicalRejectsUnrestrictedCIDRs(t *testing.T) {
	for _, values := range [][]string{
		{"0.0.0.0/0"},
		{"0.0.0.0/1", "128.0.0.0/1"},
		{"10.0.0.1/24"},
		{"10.0.0.0/24", "::/1", "8000::/1"},
	} {
		if _, err := Parse(values); err == nil {
			t.Errorf("unsafe CIDRs accepted: %v", values)
		}
	}
}

func TestIntersectionOfCanonicalPolicies(t *testing.T) {
	a, err := Parse([]string{"10.0.0.0/23", "192.0.2.1/32", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]string{"10.0.0.0/24", "10.0.1.64/26", "192.0.2.2/32", "2001:db8:2::/48"})
	if err != nil {
		t.Fatal(err)
	}
	got := Strings(Intersect(a, b))
	want := []string{"10.0.0.0/24", "10.0.1.64/26", "2001:db8:2::/48"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("intersection %v, want %v", got, want)
	}
}
