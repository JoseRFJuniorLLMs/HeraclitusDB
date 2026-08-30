use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::evidence::command_text;
use crate::manifest::EnvironmentManifest;

fn first_nonempty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty() && value.trim() != "unavailable")
        .cloned()
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn powershell(script: &str, cwd: &Path) -> String {
    command_text(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
        cwd,
    )
}

fn linux_value(file: &str, prefix: &str) -> String {
    std::fs::read_to_string(file)
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                line.strip_prefix(prefix)
                    .map(|value| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unavailable".to_owned())
}

pub fn capture(repo: &Path) -> EnvironmentManifest {
    let windows = cfg!(target_os = "windows");
    let cpu_model = if windows {
        powershell(
            "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)",
            repo,
        )
    } else {
        linux_value("/proc/cpuinfo", "model name\t:")
    };
    let memory_bytes = if windows {
        powershell(
            "[uint64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            repo,
        )
        .parse()
        .unwrap_or(0)
    } else {
        linux_value("/proc/meminfo", "MemTotal:")
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1024)
    };
    let storage_model = if windows {
        powershell(
            "(Get-CimInstance Win32_DiskDrive | Select-Object -First 1 -ExpandProperty Model)",
            repo,
        )
    } else {
        command_text("lsblk", &["-dn", "-o", "MODEL"], repo)
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("unavailable")
            .trim()
            .to_owned()
    };
    let filesystem = if windows {
        powershell(
            "(Get-Volume -DriveLetter ([IO.Path]::GetPathRoot((Get-Location).Path).Substring(0,1)) | Select-Object -ExpandProperty FileSystem)",
            repo,
        )
    } else {
        command_text("findmnt", &["-n", "-o", "FSTYPE", "--target", "."], repo)
    };
    let kernel = if windows {
        powershell("[Environment]::OSVersion.VersionString", repo)
    } else {
        command_text("uname", &["-sr"], repo)
    };
    let virtualization = if windows {
        let value = powershell(
            "(Get-CimInstance Win32_ComputerSystem | ForEach-Object { \"$($_.Manufacturer) $($_.Model)\" })",
            repo,
        );
        (value != "unavailable").then_some(value)
    } else {
        let value = command_text("systemd-detect-virt", &[], repo);
        (value != "none" && value != "unavailable").then_some(value)
    };

    let mut relevant_settings = BTreeMap::new();
    relevant_settings.insert(
        "swap".to_owned(),
        if windows {
            powershell(
                "(Get-CimInstance Win32_PageFileUsage | Measure-Object AllocatedBaseSize -Sum).Sum",
                repo,
            )
        } else {
            linux_value("/proc/meminfo", "SwapTotal:")
        },
    );
    relevant_settings.insert(
        "rust_target".to_owned(),
        format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
    );
    for key in [
        "RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "HERACLITUS_STORAGE_FORMAT",
        "HERACLITUS_FSYNC_POLICY",
    ] {
        if let Ok(value) = std::env::var(key) {
            relevant_settings.insert(key.to_owned(), value);
        }
    }

    let os_candidates = [
        std::env::var("OS").unwrap_or_default(),
        std::env::consts::OS.to_owned(),
    ];
    EnvironmentManifest {
        cpu_model: first_nonempty(&[cpu_model]),
        cpu_count: std::thread::available_parallelism()
            .map(|value| value.get() as u32)
            .unwrap_or(0),
        memory_bytes,
        storage_model,
        filesystem,
        os: first_nonempty(&os_candidates),
        kernel,
        network: std::env::var("HERACLITUS_QUALIFICATION_NETWORK")
            .unwrap_or_else(|_| "unavailable".to_owned()),
        virtualization,
        architecture: std::env::consts::ARCH.to_owned(),
        relevant_settings,
    }
}

pub fn tool_version(program: &str, args: &[&str], repo: &Path) -> String {
    let output = Command::new(program).args(args).current_dir(repo).output();
    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            first_nonempty(&[stdout, stderr])
        }
        _ => "unavailable".to_owned(),
    }
}
