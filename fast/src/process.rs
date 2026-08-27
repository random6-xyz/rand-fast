use std::{collections::BTreeSet, fs, io, path::PathBuf};

fn proc_path(pid: u32, suffix: &str) -> PathBuf {
    let mut path = PathBuf::from("/proc");
    path.push(pid.to_string());
    path.push(suffix);
    path
}

pub fn read_name(pid: u32) -> io::Result<String> {
    let name = fs::read_to_string(proc_path(pid, "comm"))?;
    let name = name.trim();
    if name.is_empty() {
        Ok("<unknown>".to_string())
    } else {
        Ok(name.to_string())
    }
}

pub fn thread_ids(pid: u32) -> io::Result<BTreeSet<u32>> {
    let mut tids = BTreeSet::new();
    for entry in fs::read_dir(proc_path(pid, "task"))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Ok(tid) = name.parse::<u32>() {
            tids.insert(tid);
        }
    }

    if tids.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("process {pid} has no visible threads"),
        ));
    }
    Ok(tids)
}

pub fn is_alive(pid: u32) -> io::Result<bool> {
    let status = match fs::read_to_string(proc_path(pid, "status")) {
        Ok(status) => status,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(status_is_alive(&status))
}

fn status_is_alive(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("State:")?.split_whitespace().next())
        != Some("Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_has_a_thread() {
        let pid = std::process::id();
        let tids = thread_ids(pid).unwrap();
        assert!(tids.contains(&pid));
    }

    #[test]
    fn current_process_is_alive() {
        assert!(is_alive(std::process::id()).unwrap());
    }

    #[test]
    fn treats_zombie_processes_as_not_alive() {
        assert!(status_is_alive("Name:\ttest\nState:\tS (sleeping)\n"));
        assert!(!status_is_alive("Name:\ttest\nState:\tZ (zombie)\n"));
    }
}
