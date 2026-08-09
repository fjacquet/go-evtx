// event.go — the typed event assembled from a decoded element tree.
//
// <System> has a fixed schema and gets typed fields. <EventData> does not: its
// <Data> children may be named or positional, names may repeat, and order
// carries meaning — so it is an ordered slice, never a map. <EventData> may
// also end in a trailing <Binary> element that is not a <Data> at all
// (testdata/system.evtx records 2-5); it gets its own field on Event rather
// than being dropped. Anything inside <EventData> that is neither is skipped
// deliberately — see the comment at that loop.
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
	Name            string `json:"name,omitempty"`
	GUID            string `json:"guid,omitempty"`
	EventSourceName string `json:"event_source_name,omitempty"`
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
	Binary    Value     `json:"binary,omitempty"` // <EventData>'s trailing <Binary>, when present
	UserData  *Node     `json:"user_data,omitempty"`
}

// attr returns the named attribute's value, or the zero Value.
func (n *Node) attr(name string) Value {
	if n == nil {
		return Value{}
	}
	for _, a := range n.Attributes {
		if a.Name == name {
			return a.Value
		}
	}
	return Value{}
}

// child returns the first child with the given name, or nil.
func (n *Node) child(name string) *Node {
	if n == nil {
		return nil
	}
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
			ev.System.Provider.EventSourceName = p.attr("EventSourceName").String()
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

	edNode, udNode := resolveEventContent(root)

	if edNode != nil {
		for i := range edNode.Children {
			c := &edNode.Children[i]
			switch c.Name {
			case "Data":
				d := Data{Name: c.attr("Name").String()}
				if c.Value != nil {
					d.Value = *c.Value
				}
				ev.EventData = append(ev.EventData, d)
			case "Binary":
				if c.Value != nil {
					ev.Binary = *c.Value
				}
			default:
				// Neither <Data> nor <Binary> — skipped deliberately: Event
				// has no slot for it (Event.EventData []Data, per the
				// design), and nothing else has been observed in the
				// measured corpus. Not an oversight.
			}
		}
	}
	if udNode != nil {
		ev.UserData = udNode
	}
	return ev, nil
}

// resolveEventContent finds root's <EventData>/<UserData> content, however it
// is encoded — see the package doc comment above for the three shapes.
// Either may be a literal child element of <Event>, or — no wrapping element
// at all — <Event>'s own bare value. contentNode follows a further nested
// BinXml substitution in either case.
//
// <EventData> has one fixed, known shape (<Data>/<Binary> children), so its
// identity is checked after resolution: a literal <EventData> child whose own
// Value resolved to something not itself named "EventData" is treated as no
// EventData at all, rather than blindly reading child elements out of an
// unrelated tree and calling whatever turned up "EventData" — the same check
// the no-wrapping-element fallback below already applies. <UserData> carries
// no such fixed shape — arbitrary XML is the entire point of it
// (testdata/system.evtx wraps <AutoBackup>, sharing no name with <UserData>
// at all), so once the literal <UserData> child itself is confirmed by name,
// whatever it resolves to — <AutoBackup>, or itself when unresolved — is
// trusted as its content; a name-equality check would reject the one real
// case this decoder has measured.
func resolveEventContent(root *Node) (edNode, udNode *Node) {
	if ed := root.child("EventData"); ed != nil {
		if cn := contentNode(ed); cn.Name == "EventData" {
			edNode = cn
		}
		return edNode, nil
	}
	if ud := root.child("UserData"); ud != nil {
		return nil, contentNode(ud)
	}
	if cn := contentNode(root); cn != root {
		switch cn.Name {
		case "EventData":
			edNode = cn
		case "UserData":
			udNode = cn
		}
	}
	return edNode, udNode
}
