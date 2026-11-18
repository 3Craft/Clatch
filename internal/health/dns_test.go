package health

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSReplyPolicy(t *testing.T) {
	name, _ := dnsmessage.NewName("example.test.")
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 15},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}}}
	reply := query
	reply.Response = true
	check := func(expectEmpty, accepted bool) {
		t.Helper()
		payload, err := reply.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validateReply(payload, query, expectEmpty); (err == nil) != accepted {
			t.Fatalf("reply %+v, expectEmpty=%v: %v", reply, expectEmpty, err)
		}
	}
	check(true, true)
	check(false, false)
	reply.RCode = dnsmessage.RCodeNameError
	check(true, false)
	reply.RCode = dnsmessage.RCodeSuccess
	reply.ID++
	check(true, false)
	reply.ID = query.ID
	reply.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET},
		Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}}}
	check(false, true)
	check(true, false)
}
