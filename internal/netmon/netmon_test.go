package netmon

import "testing"

func TestDedupeConnections(t *testing.T) {
	in := []Conn{
		{Proc: "p", PID: "1", Proto: "TCP", Local: "*:5000", State: "LISTEN"},
		{Proc: "p", PID: "1", Proto: "TCP", Local: "*:5000", State: "LISTEN"},
		{Proc: "p", PID: "1", Proto: "TCP", Local: "*:7000", State: "LISTEN"},
	}
	got := dedupe(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique connections, got %+v", got)
	}
}
