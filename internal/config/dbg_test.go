package config

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestDbg(t *testing.T) {
	c := Defaults()
	b, _ := json.Marshal(c)
	var m map[string]any
	json.Unmarshal(b, &m)
	fmt.Println("gc:", m["gc"])
}
