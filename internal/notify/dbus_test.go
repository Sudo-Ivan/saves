// SPDX-License-Identifier: 0BSD

package notify

import (
	"bufio"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type fakeNotif struct{ got *[]call }

func (f *fakeNotif) Notify(app string, id uint32, icon, summary, body string,
	actions []string, hints map[string]dbus.Variant, expiry int32) (uint32, *dbus.Error) {
	*f.got = append(*f.got, call{app, summary, body})
	return 1, nil
}

type call struct{ app, summary, body string }

// fakeNotifications registers org.freedesktop.Notifications and records calls.
func TestDBusReal(t *testing.T) {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon missing")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--print-address=1", "--nofork")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	rd := bufio.NewReader(out)
	addr, err := rd.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	addr = strings.TrimSpace(addr)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Skipf("session bus: %v", err)
	}
	defer conn.Close()
	reply, err := conn.RequestName("org.freedesktop.Notifications", dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("name %v %v", reply, err)
	}
	var got []call
	err = conn.Export(&fakeNotif{got: &got},
		"/org/freedesktop/Notifications", "org.freedesktop.Notifications")
	if err != nil {
		t.Fatal(err)
	}
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	var id uint32
	if err := obj.Call("org.freedesktop.Notifications.Notify", 0,
		"saves", uint32(0), "", "Hello", "World",
		[]string{}, map[string]dbus.Variant{}, int32(5000)).Store(&id); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if len(got) != 1 || got[0].summary != "Hello" || got[0].body != "World" {
		t.Fatalf("calls %+v", got)
	}
}
