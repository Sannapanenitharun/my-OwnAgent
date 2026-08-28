package architecture

import (
	"testing"

	"github.com/obsagent/observability-agent/internal/modules/discovery"
	"github.com/obsagent/observability-agent/internal/modules/host"
)

// TestFilesystemPolicyAgreesAcrossModules guards a join.
//
// Two modules describe the same mounts from different angles: discovery says
// which filesystems EXIST, and the host module says how FULL they are. The
// fleet view joins the two on the mount point, so a mount either module refuses
// is a row the other cannot complete.
//
// They drifted. Discovery admitted overlay and tmpfs; the host module excluded
// overlay by type and the tmpfs mounts by their /run and /dev prefixes. A
// container host therefore listed 29 filesystems and measured 3, and the 26
// that could never be measured -- 21 of them Docker layer overlays -- buried
// the three an operator would actually alert on. Neither module was wrong on
// its own, which is exactly why nothing caught it.
//
// This test does not demand identical lists. The host module excludes types
// discovery has no reason to know about, and that is fine. It demands that
// discovery never ADMITS something the host module will refuse to measure,
// because that asymmetry is the one that produces unjoinable rows.
func TestFilesystemPolicyAgreesAcrossModules(t *testing.T) {
	hostSettings := host.DefaultSettings()
	discoverySettings := discovery.DefaultSettings()

	for _, fsType := range hostSettings.FilesystemTypeExclude {
		if discovery.AdmitsFilesystemType(discoverySettings, fsType) {
			t.Errorf("discovery admits filesystem type %q that the host module "+
				"will never measure: every such mount becomes a row reading "+
				"\"not measured\"", fsType)
		}
	}

	for _, mount := range hostSettings.FilesystemExclude {
		if discovery.AdmitsMountpoint(discoverySettings, mount) {
			t.Errorf("discovery admits mountpoint %q that the host module "+
				"excludes; the usage join can never complete for it", mount)
		}
	}
}

// TestTheMountsThatMatterAreStillAdmitted is the other half. An exclusion list
// that agrees by excluding everything would pass the test above.
func TestTheMountsThatMatterAreStillAdmitted(t *testing.T) {
	s := discovery.DefaultSettings()
	for _, mount := range []string{"/", "/boot", "/boot/efi", "/var", "/home", "/data"} {
		if !discovery.AdmitsMountpoint(s, mount) {
			t.Errorf("discovery excludes %q, which is real storage", mount)
		}
	}
	for _, fsType := range []string{"ext4", "xfs", "btrfs", "zfs", "vfat", "ntfs", "apfs"} {
		if !discovery.AdmitsFilesystemType(s, fsType) {
			t.Errorf("discovery excludes filesystem type %q, which is real storage", fsType)
		}
	}
}
