// event.go — the typed event assembled from a decoded element tree.
//
// <System> has a fixed schema and gets typed fields. <EventData> does not: its
// <Data> children may be named or positional, names may repeat, and order
// carries meaning — so it is an ordered slice, never a map.
//
// Real Windows records (testdata/system.evtx, ground-truthed by
// testdata/system-expected-windows.xml) wrap <EventData>/<UserData> in two
// different shapes, and go-evtx's own writer uses a third:
//
//  1. A literal child element of <Event> whose OWN content is a nested
//     BinXml-typed substitution, not literal children — record 1's
//     <UserData><AutoBackup>...</AutoBackup></UserData>. The <UserData>
//     element itself carries no attributes and no direct Children; what
//     decodeBinXMLFragment recursed into hangs off its Value.Node().
//  2. No wrapping element at all: <Event>'s own content is <System> followed
//     directly by a bare substitution, and THAT substitution's nested
//     fragment happens to be named "EventData" — records 2-5. See
//     setElementValue's doc comment in binxml_decode.go for why <Event> can
//     carry a Value despite also having Children.
//  3. go-evtx's own writer: <EventData> as a literal child of <Event> with
//     literal <Data> children — no nested substitution anywhere in the
//     shape, the simplest of the three.
//
// contentNode below resolves all three to the same thing: the node whose
// Children are the actual <Data> elements (case 2/3) or whose identity IS the
// UserData payload (case 1's <AutoBackup>).
package evtx

import (
	"fmt"
	"time"
)

// Provider identifies the source of an event.
type Provider struct {
	Name string `json:"name,omitempty"`
	GUID string `json:"guid,omitempty"`
}

// System is the fixed-schema <System> block.
type System struct {
	Provider      Provider  `json:"provider"`
	EventID       uint16    `json:"event_id"`
	Qualifiers    uint16    `json:"qualifiers,omitempty"`
	Version       uint8     `json:"version,omitempty"`
	Level         uint8     `json:"level"`
	Task          uint16    `json:"task,omitempty"`
	Opcode        uint8     `json:"opcode,omitempty"`
	Keywords      uint64    `json:"keywords,omitempty"`
	TimeCreated   time.Time `json:"time_created"`
	EventRecordID uint64    `json:"event_record_id"`
	ActivityID    string    `json:"activity_id,omitempty"`
	ProcessID     uint32    `json:"process_id,omitempty"`
	ThreadID      uint32    `json:"thread_id,omitempty"`
	Channel       string    `json:"channel,omitempty"`
	Computer      string    `json:"computer,omitempty"`
	UserID        string    `json:"user_id,omitempty"`
}

// Data is one <Data> element. Name is empty for positional entries.
type Data struct {
	Name  string `json:"name"`
	Value Value  `json:"value"`
}

// Event is a fully decoded event record.
type Event struct {
	RecordID  uint64    `json:"record_id"`
	Timestamp time.Time `json:"timestamp"`
	System    System    `json:"system"`
	EventData []Data    `json:"event_data,omitempty"`
	UserData  *Node     `json:"user_data,omitempty"`
}

// attr returns the named attribute's value, or the zero Value.
func (n *Node) attr(name string) Value {
	for _, a := range n.Attributes {
		if a.Name == name {
			return a.Value
		}
	}
	return Value{}
}

// child returns the first child with the given name, or nil.
func (n *Node) child(name string) *Node {
	for i := range n.Children {
		if n.Children[i].Name == name {
			return &n.Children[i]
		}
	}
	return nil
}

// u64 reads a node's scalar content, or 0 when absent.
func (n *Node) u64() uint64 {
	if n == nil || n.Value == nil {
		return 0
	}
	v, _ := n.Value.Uint64()
	return v
}

// text reads a node's content as text, or "" when absent.
func (n *Node) text() string {
	if n == nil || n.Value == nil {
		return ""
	}
	return n.Value.String()
}

// contentNode resolves n to the node that actually holds its content. When n
// itself carries a value that is a decoded BinXml fragment (Value.Node() !=
// nil), that nested fragment's root is n's real content — measured on
// testdata/system.evtx's <UserData> (case 1 above) and, at the <Event> root
// itself, its <EventData> (case 2). Otherwise n's own Children already are
// the content (case 3, and every fixed-schema element under <System>).
func contentNode(n *Node) *Node {
	if n == nil {
		return nil
	}
	if n.Value != nil {
		if nested := n.Value.Node(); nested != nil {
			return nested
		}
	}
	return n
}

// eventFromNode assembles an Event from a decoded <Event> tree.
func eventFromNode(root *Node) (*Event, error) {
	if root == nil {
		return nil, fmt.Errorf("go_evtx: no root element")
	}
	if root.Name != "Event" {
		return nil, fmt.Errorf("go_evtx: root element is %q, want \"Event\"", root.Name)
	}
	ev := &Event{}

	if sys := root.child("System"); sys != nil {
		if p := sys.child("Provider"); p != nil {
			ev.System.Provider.Name = p.attr("Name").String()
			ev.System.Provider.GUID = p.attr("Guid").String()
		}
		if e := sys.child("EventID"); e != nil {
			ev.System.EventID = uint16(e.u64())
			if q, ok := e.attr("Qualifiers").Uint64(); ok {
				ev.System.Qualifiers = uint16(q)
			}
		}
		ev.System.Version = uint8(sys.child("Version").u64())
		ev.System.Level = uint8(sys.child("Level").u64())
		ev.System.Task = uint16(sys.child("Task").u64())
		ev.System.Opcode = uint8(sys.child("Opcode").u64())
		ev.System.Keywords = sys.child("Keywords").u64()
		ev.System.EventRecordID = sys.child("EventRecordID").u64()
		ev.System.Channel = sys.child("Channel").text()
		ev.System.Computer = sys.child("Computer").text()
		if tc := sys.child("TimeCreated"); tc != nil {
			if ts, ok := tc.attr("SystemTime").Time(); ok {
				ev.System.TimeCreated = ts
			}
		}
		if c := sys.child("Correlation"); c != nil {
			ev.System.ActivityID = c.attr("ActivityID").String()
		}
		if x := sys.child("Execution"); x != nil {
			pid, _ := x.attr("ProcessID").Uint64()
			tid, _ := x.attr("ThreadID").Uint64()
			ev.System.ProcessID = uint32(pid)
			ev.System.ThreadID = uint32(tid)
		}
		if s := sys.child("Security"); s != nil {
			ev.System.UserID = s.attr("UserID").String()
		}
	}

	// EventData/UserData: try a literal child of <Event> first (go-evtx's own
	// writer, and testdata/system.evtx record 1's <UserData>); fall back to
	// <Event>'s own bare value when neither exists as a child element at all
	// (testdata/system.evtx records 2-5's <EventData> — see the package doc
	// comment above). contentNode resolves whichever shape was found through
	// any nested BinXml substitution.
	var edNode, udNode *Node
	switch {
	case root.child("EventData") != nil:
		edNode = contentNode(root.child("EventData"))
	case root.child("UserData") != nil:
		udNode = contentNode(root.child("UserData"))
	default:
		if cn := contentNode(root); cn != root {
			switch cn.Name {
			case "EventData":
				edNode = cn
			case "UserData":
				udNode = cn
			}
		}
	}

	if edNode != nil {
		for i := range edNode.Children {
			c := &edNode.Children[i]
			if c.Name != "Data" {
				continue
			}
			d := Data{Name: c.attr("Name").String()}
			if c.Value != nil {
				d.Value = *c.Value
			}
			ev.EventData = append(ev.EventData, d)
		}
	}
	if udNode != nil {
		ev.UserData = udNode
	}
	return ev, nil
}
