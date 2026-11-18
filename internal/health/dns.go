package health

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsTimeout = 4 * time.Second

func DNS(ctx context.Context, server netip.AddrPort, transport, domain string, kind dnsmessage.Type, empty bool) (int, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return 0, err
	}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return 0, err
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}},
	}
	request, err := query.Pack()
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, transport, server.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	payload, err := exchangeDNS(conn, transport, request)
	if err != nil {
		return 0, err
	}
	return validateReply(payload, query, empty)
}

func exchangeDNS(conn net.Conn, transport string, request []byte) ([]byte, error) {
	var length [2]byte
	if transport == "tcp4" {
		binary.BigEndian.PutUint16(length[:], uint16(len(request)))
		request = append(length[:], request...)
	}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	if transport == "tcp4" {
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		payload := make([]byte, binary.BigEndian.Uint16(length[:]))
		_, err := io.ReadFull(conn, payload)
		return payload, err
	}
	payload := make([]byte, 65535)
	n, err := conn.Read(payload)
	return payload[:n], err
}

func validateReply(payload []byte, query dnsmessage.Message, empty bool) (int, error) {
	var reply dnsmessage.Message
	if err := reply.Unpack(payload); err != nil {
		return 0, fmt.Errorf("invalid DNS reply: %w", err)
	}
	if reply.ID != query.ID || !reply.Response || reply.OpCode != 0 || reply.Truncated || reply.RCode != dnsmessage.RCodeSuccess ||
		len(reply.Questions) != 1 {
		return 0, fmt.Errorf("DNS reply does not match a complete successful query")
	}
	q, r := query.Questions[0], reply.Questions[0]
	if q.Class != r.Class || q.Type != r.Type || !strings.EqualFold(q.Name.String(), r.Name.String()) {
		return 0, fmt.Errorf("DNS question in reply differs from the request")
	}
	if empty {
		if len(reply.Answers) != 0 {
			return 0, fmt.Errorf("IPv4-only DNS must return an empty successful AAAA reply")
		}
		return 0, nil
	}
	for _, answer := range reply.Answers {
		if answer.Header.Type == q.Type && answer.Header.Class == q.Class {
			return len(reply.Answers), nil
		}
	}
	return 0, fmt.Errorf("DNS reply contains no requested address records")
}
