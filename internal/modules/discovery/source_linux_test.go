//go:build linux

package discovery

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// cgroupTree builds a fake cgroup directory. procs maps a path relative to the
// root to the PIDs in that cgroup's cgroup.procs; an empty slice writes an
// empty file, which is what a delegating unit's own directory looks like.
func cgroupTree(t *testing.T, procs map[string][]int) string {
	t.Helper()
	root := t.TempDir()
	for rel, pids := range procs {
		dir := filepath.Join(root, rel)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var body []byte
		for _, p := range pids {
			body = append(body, []byte(strconv.Itoa(p)+"\n")...)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestMainPIDComesFromTheUnitsOwnCgroup(t *testing.T) {
	root := cgroupTree(t, map[string][]int{"ssh.service": {900, 812, 1004}})
	s := &linuxSource{buf: make([]byte, 4096)}
	pid, ok := s.mainPIDOf(filepath.Join(root, "ssh.service"))
	if !ok {
		t.Fatal("no PID found")
	}
	// The lowest PID: a unit's main process starts before the workers it forks.
	if pid != 812 {
		t.Errorf("pid = %d, want 812 (the lowest)", pid)
	}
}

func TestDelegatedUnitReportsThePIDFromItsChildCgroup(t *testing.T) {
	// systemd-udevd delegates: systemd creates the unit's cgroup, and udevd
	// puts its workers in a child called "udev". Reading only the parent found
	// an empty cgroup.procs and reported a running daemon as state=unknown
	// with no PID.
	root := cgroupTree(t, map[string][]int{
		"systemd-udevd.service":      {},
		"systemd-udevd.service/udev": {497744},
	})
	s := &linuxSource{buf: make([]byte, 4096)}
	pid, ok := s.mainPIDOf(filepath.Join(root, "systemd-udevd.service"))
	if !ok {
		t.Fatal("no PID found; a delegated unit still has a main process")
	}
	if pid != 497744 {
		t.Errorf("pid = %d, want 497744 from the child cgroup", pid)
	}
}

func TestShallowestChildWins(t *testing.T) {
	// The main process sits at the top of a delegated subtree. A worker buried
	// deeper must not be mistaken for it.
	root := cgroupTree(t, map[string][]int{
		"app.service":            {},
		"app.service/main":       {500},
		"app.service/a/b/buried": {100},
	})
	s := &linuxSource{buf: make([]byte, 4096)}
	pid, ok := s.mainPIDOf(filepath.Join(root, "app.service"))
	if !ok {
		t.Fatal("no PID found")
	}
	if pid != 500 {
		t.Errorf("pid = %d, want 500 -- breadth first, not lowest overall", pid)
	}
}

func TestTrulyEmptyUnitStaysUnknown(t *testing.T) {
	// A oneshot unit that has exited leaves an empty cgroup with no children.
	// Reporting it as running would be a lie; "unknown" is what is known.
	root := cgroupTree(t, map[string][]int{"cloud-final.service": {}})
	s := &linuxSource{buf: make([]byte, 4096)}
	if pid, ok := s.mainPIDOf(filepath.Join(root, "cloud-final.service")); ok {
		t.Errorf("pid = %d, want no PID for an exited oneshot unit", pid)
	}
}

func TestDeepCgroupTreeIsBounded(t *testing.T) {
	// A container manager delegates a subtree with one directory per container,
	// and this runs in the collection path. The walk must stop rather than
	// scale with the workload.
	procs := map[string][]int{"docker.service": {}}
	deep := "docker.service"
	for i := 0; i < maxCgroupDepth+4; i++ {
		deep = filepath.Join(deep, "d")
		procs[deep] = nil
	}
	procs[filepath.Join(deep, "leaf")] = []int{4242}
	root := cgroupTree(t, procs)

	s := &linuxSource{buf: make([]byte, 4096)}
	if pid, ok := s.mainPIDOf(filepath.Join(root, "docker.service")); ok {
		t.Errorf("pid = %d found past the depth bound; the walk is unbounded", pid)
	}
}

func TestUnreadableCgroupIsNotFatal(t *testing.T) {
	s := &linuxSource{buf: make([]byte, 4096)}
	if _, ok := s.mainPIDOf(filepath.Join(t.TempDir(), "does-not-exist.service")); ok {
		t.Error("a missing cgroup reported a PID")
	}
}
