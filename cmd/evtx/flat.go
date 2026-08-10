package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	evtx "github.com/fjacquet/go-evtx"
)

// reservedKeys are the root keys the flat shape will not let an EventData
// entry take. They are read from evtx.System's struct tags rather than listed
// by hand, for two reasons: adding a System field cannot silently open a
// collision, and several tags carry omitempty, so a set derived from the
// record in hand would reserve different keys for different records of the
// same file.
var reservedKeys = buildReservedKeys()

func buildReservedKeys() map[string]bool {
	keys := map[string]bool{
		"record_id": true,
		"timestamp": true,
		"binary":    true,
		"user_data": true,
		// Provider is one nested object in the faithful shape and three scalar
		// keys here. "provider" is System's own tag for that object and would
		// be picked up by the reflection pass below anyway; it is listed
		// explicitly so all three keys of the projection appear together. The
		// other two exist only in this shape.
		"provider":                   true,
		"provider_guid":              true,
		"provider_event_source_name": true,
	}
	t := reflect.TypeOf(evtx.System{})
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}

// flatten projects an Event onto a single JSON level and reports how many
// EventData keys had to be renamed.
//
// The rule: an EventData entry takes its own name as its root key when that
// name is non-empty, collides with no reserved key, and has not already been
// used. Otherwise its key is data_<i>, where i is the entry's absolute index,
// followed by _<Name> when a name exists.
//
// user_data stays nested even here: it is an arbitrary XML tree, and
// flattening it would mean inventing a path convention. "Flat" describes
// EventData, not the whole record.
func flatten(ev *evtx.Event) (map[string]any, int) {
	root := map[string]any{
		"record_id": ev.RecordID,
		"timestamp": ev.Timestamp,
	}

	// System is lifted through its own JSON tags rather than field by field,
	// so it cannot fall out of step with the faithful shape.
	var sys map[string]any
	if b, err := json.Marshal(ev.System); err == nil {
		_ = json.Unmarshal(b, &sys)
	}
	delete(sys, "provider")
	for k, v := range sys {
		root[k] = v
	}

	if ev.System.Provider.Name != "" {
		root["provider"] = ev.System.Provider.Name
	}
	if ev.System.Provider.GUID != "" {
		root["provider_guid"] = ev.System.Provider.GUID
	}
	if ev.System.Provider.EventSourceName != "" {
		root["provider_event_source_name"] = ev.System.Provider.EventSourceName
	}
	if !ev.Binary.IsAbsent() {
		root["binary"] = ev.Binary
	}
	if ev.UserData != nil {
		root["user_data"] = ev.UserData
	}

	used := make(map[string]bool, len(ev.EventData))
	relocated := 0
	for i, d := range ev.EventData {
		key := d.Name
		if key == "" || reservedKeys[key] || used[key] {
			relocated++
			key = uniqueKey(fallbackKey(i, d.Name), used)
		}
		used[key] = true
		root[key] = d.Value
	}
	return root, relocated
}

// fallbackKey is the generated key for an entry that cannot take its own name:
// data_<i>, where i is the entry's absolute index, followed by _<Name> when a
// name exists.
func fallbackKey(i int, name string) string {
	key := fmt.Sprintf("data_%d", i)
	if name != "" {
		key += "_" + name
	}
	return key
}

// uniqueKey returns key, or the first key_2, key_3, … that is neither reserved
// nor already used.
//
// The generated name is not inherently safe: a record carrying
// <Data Name="data_3"> at index 0 and an unnamed <Data> at index 3 generates
// data_3 twice, and writing it unconditionally made the second entry
// overwrite the first while relocated still counted it as a successful
// rename. Silent loss is exactly what this shape promises not to do, so the
// generated key is checked against the same two sets the original name was.
func uniqueKey(key string, used map[string]bool) string {
	if !used[key] && !reservedKeys[key] {
		return key
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s_%d", key, n)
		if !used[candidate] && !reservedKeys[candidate] {
			return candidate
		}
	}
}
