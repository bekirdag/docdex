use std::path::PathBuf;

use sysinfo::Disks;

use crate::hardware;

#[derive(Debug, Clone)]
pub struct SetupHardware {
    pub total_memory_gb: f64,
    pub free_disk_bytes: u64,
    pub cpu_count: usize,
}

impl SetupHardware {
    pub fn recommend_phi(&self) -> bool {
        self.total_memory_gb >= 8.0 && self.free_disk_bytes >= 3 * 1024 * 1024 * 1024
    }

    pub fn recommended_class(&self) -> &'static str {
        if self.total_memory_gb >= 16.0 && self.free_disk_bytes >= 6 * 1024 * 1024 * 1024 {
            "standard"
        } else if self.recommend_phi() {
            "light"
        } else {
            "ultra-light"
        }
    }
}

pub fn detect() -> SetupHardware {
    let profile = hardware::detect_hardware();
    let cpu_count = sysinfo::System::new_all().cpus().len();
    let home = home_dir();
    let free_disk_bytes = detect_free_disk_bytes(home);
    SetupHardware {
        total_memory_gb: profile.total_memory_gb(),
        free_disk_bytes,
        cpu_count,
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn detect_free_disk_bytes(home: Option<PathBuf>) -> u64 {
    let disks = Disks::new_with_refreshed_list();
    let home_path = home.unwrap_or_else(|| PathBuf::from("/"));
    let mut best_match = None;
    for disk in disks.list() {
        let mount = disk.mount_point();
        if home_path.starts_with(mount) {
            let len = mount.as_os_str().len();
            if best_match
                .map(|(best_len, _)| len > best_len)
                .unwrap_or(true)
            {
                best_match = Some((len, disk.available_space()));
            }
        }
    }
    best_match.map(|(_, free)| free).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::SetupHardware;

    #[test]
    fn recommend_phi_requires_ram_and_disk() {
        let low_ram = SetupHardware {
            total_memory_gb: 4.0,
            free_disk_bytes: 10 * 1024 * 1024 * 1024,
            cpu_count: 4,
        };
        assert!(!low_ram.recommend_phi());

        let low_disk = SetupHardware {
            total_memory_gb: 16.0,
            free_disk_bytes: 1 * 1024 * 1024 * 1024,
            cpu_count: 8,
        };
        assert!(!low_disk.recommend_phi());

        let ok = SetupHardware {
            total_memory_gb: 16.0,
            free_disk_bytes: 4 * 1024 * 1024 * 1024,
            cpu_count: 8,
        };
        assert!(ok.recommend_phi());
    }

    #[test]
    fn recommended_class_tracks_thresholds() {
        let ultra = SetupHardware {
            total_memory_gb: 4.0,
            free_disk_bytes: 2 * 1024 * 1024 * 1024,
            cpu_count: 4,
        };
        assert_eq!(ultra.recommended_class(), "ultra-light");

        let light = SetupHardware {
            total_memory_gb: 8.0,
            free_disk_bytes: 3 * 1024 * 1024 * 1024,
            cpu_count: 8,
        };
        assert_eq!(light.recommended_class(), "light");

        let standard = SetupHardware {
            total_memory_gb: 16.0,
            free_disk_bytes: 8 * 1024 * 1024 * 1024,
            cpu_count: 8,
        };
        assert_eq!(standard.recommended_class(), "standard");
    }
}
