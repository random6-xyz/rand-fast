use std::{
    alloc::{Layout, alloc, dealloc},
    fs::{File, OpenOptions},
    hint::black_box,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand};

const CHUNK_SIZE: usize = 4096;

#[derive(Debug, Parser)]
#[command(
    name = "fast-workload",
    about = "Workload fixtures for validating fast subcommands"
)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Debug, Subcommand)]
enum Mode {
    /// Sequential or random O_DIRECT file reads (validates `fast io`).
    #[command(name = "io-hog")]
    Io(IoHogArgs),
    /// Loopback TCP request/response traffic (validates `fast net`).
    #[command(name = "net-hog")]
    Net(NetHogArgs),
    /// Futex contention across N threads (validates `fast offcpu`).
    #[command(name = "lock-hog")]
    Lock(LockHogArgs),
    /// Allocation and page-fault churn (validates `fast memory`).
    #[command(name = "mem-hog")]
    Mem(MemHogArgs),
}

#[derive(Debug, Clone, Args)]
struct IoHogArgs {
    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of reader threads.
    #[arg(long, default_value_t = 1)]
    workers: usize,

    /// File to read. Created (and overwritten) at startup.
    #[arg(long, default_value = "/tmp/fast-workload-io")]
    path: PathBuf,

    /// File size in MiB.
    #[arg(long, default_value_t = 64)]
    size_mib: u64,

    /// Read at random offsets instead of sequentially.
    #[arg(long)]
    random: bool,
}

#[derive(Debug, Clone, Args)]
struct NetHogArgs {
    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of client threads, each with its own loopback connection.
    #[arg(long, default_value_t = 2)]
    workers: usize,
}

#[derive(Debug, Clone, Args)]
struct LockHogArgs {
    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of threads contending on one futex word.
    #[arg(long, default_value_t = 4)]
    workers: usize,
}

#[derive(Debug, Clone, Args)]
struct MemHogArgs {
    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of faulting threads.
    #[arg(long, default_value_t = 1)]
    workers: usize,

    /// Fresh anonymous memory mapped and faulted per round, in MiB.
    #[arg(long, default_value_t = 64)]
    size_mib: usize,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.mode {
        Mode::Io(args) => run_io_hog(args),
        Mode::Net(args) => run_net_hog(args),
        Mode::Lock(args) => run_lock_hog(args),
        Mode::Mem(args) => run_mem_hog(args),
    };

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn run_io_hog(args: IoHogArgs) -> Result<(), String> {
    if args.workers == 0 {
        return Err("workers must be greater than zero".to_string());
    }
    if args.size_mib == 0 {
        return Err("size-mib must be greater than zero".to_string());
    }

    let file_size = args.size_mib * 1024 * 1024;
    prepare_file(&args.path, file_size)?;

    println!(
        "io-hog pid: {} file: {} size: {} MiB workers: {} pattern: {}",
        std::process::id(),
        args.path.display(),
        args.size_mib,
        args.workers,
        if args.random { "random" } else { "sequential" },
    );

    let cursor = Arc::new(AtomicU64::new(0));
    let bytes_read = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + args.duration;
    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let cursor = Arc::clone(&cursor);
        let bytes_read = Arc::clone(&bytes_read);
        let path = args.path.clone();
        handles.push(
            thread::Builder::new()
                .name(format!("io-hog-{worker}"))
                .spawn(move || {
                    io_worker(&path, file_size, args.random, worker, deadline, &cursor, &bytes_read)
                })
                .map_err(|error| format!("failed to spawn io worker: {error}"))?,
        );
    }

    join_workers(handles)?;
    println!(
        "io-hog: read {} bytes in {} reads",
        bytes_read.load(Ordering::Relaxed),
        bytes_read.load(Ordering::Relaxed) / CHUNK_SIZE as u64,
    );
    Ok(())
}

fn prepare_file(path: &PathBuf, size: u64) -> Result<(), String> {
    let mut file = File::create(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    let chunk = vec![0u8; CHUNK_SIZE];
    let mut written = 0u64;
    while written < size {
        let to_write = (size - written).min(CHUNK_SIZE as u64) as usize;
        file.write_all(&chunk[..to_write])
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        written += to_write as u64;
    }
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))?;
    Ok(())
}

fn io_worker(
    path: &PathBuf,
    file_size: u64,
    random: bool,
    worker: usize,
    deadline: Instant,
    cursor: &AtomicU64,
    bytes_read: &AtomicU64,
) -> Result<(), String> {
    let file = open_direct(path)?;
    let fd = file.as_raw_fd();

    // O_DIRECT requires page-aligned buffers and offsets.
    let layout = Layout::from_size_align(CHUNK_SIZE, CHUNK_SIZE)
        .map_err(|error| format!("buffer layout: {error}"))?;
    let buffer = unsafe { alloc(layout) };
    if buffer.is_null() {
        return Err("failed to allocate the read buffer".to_string());
    }

    let mut seed = (worker as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15);
    let mut offset;
    while Instant::now() < deadline {
        if random {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            offset = seed % file_size;
        } else {
            offset = cursor.fetch_add(CHUNK_SIZE as u64, Ordering::Relaxed) % file_size;
        }

        let n = unsafe {
            libc::pread(
                fd,
                buffer.cast(),
                CHUNK_SIZE,
                offset as libc::off_t,
            )
        };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            unsafe { dealloc(buffer, layout) };
            return Err(format!("pread at offset {offset}: {error}"));
        }
        black_box(unsafe { buffer.read_volatile() });
        bytes_read.fetch_add(n as u64, Ordering::Relaxed);
    }

    unsafe { dealloc(buffer, layout) };
    Ok(())
}

fn open_direct(path: &PathBuf) -> Result<File, String> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(direct_error) => {
            // tmpfs and some overlays reject O_DIRECT; fall back loudly.
            eprintln!(
                "warning: O_DIRECT unsupported on {} ({}); falling back to buffered reads",
                path.display(),
                direct_error
            );
            let mut file = File::open(path).map_err(|error| format!("open: {error}"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|error| format!("seek: {error}"))?;
            Ok(file)
        }
    }
}

fn run_net_hog(args: NetHogArgs) -> Result<(), String> {
    if args.workers == 0 {
        return Err("workers must be greater than zero".to_string());
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("bind loopback: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("local addr: {error}"))?
        .port();

    println!(
        "net-hog pid: {} endpoint: 127.0.0.1:{port} workers: {}",
        std::process::id(),
        args.workers,
    );

    let round_trips = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + args.duration;

    let server = thread::Builder::new()
        .name("net-hog-server".to_string())
        .spawn(move || echo_server(listener, deadline))
        .map_err(|error| format!("failed to spawn server: {error}"))?;

    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let round_trips = Arc::clone(&round_trips);
        handles.push(
            thread::Builder::new()
                .name(format!("net-hog-client-{worker}"))
                .spawn(move || net_client(port, deadline, &round_trips))
                .map_err(|error| format!("failed to spawn client: {error}"))?,
        );
    }

    join_workers(handles)?;
    // Give the server a moment to drain and exit.
    let _ = server.join();
    println!(
        "net-hog: {} round trips over {port}",
        round_trips.load(Ordering::Relaxed),
    );
    Ok(())
}

fn echo_server(listener: std::net::TcpListener, deadline: Instant) {
    let _ = listener.set_nonblocking(true);
    while Instant::now() < deadline + Duration::from_secs(1) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = thread::Builder::new()
                    .name("net-hog-echo".to_string())
                    .spawn(move || echo_connection(stream));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn echo_connection(mut stream: std::net::TcpStream) {
    let mut buffer = [0u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn net_client(port: u16, deadline: Instant, round_trips: &AtomicU64) -> Result<(), String> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .map_err(|error| format!("connect 127.0.0.1:{port}: {error}"))?;
    let _ = stream.set_nodelay(true);

    let mut request = [0u8; 256];
    for (i, byte) in request.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let mut response = [0u8; 256];

    while Instant::now() < deadline {
        stream
            .write_all(&request)
            .map_err(|error| format!("write: {error}"))?;
        stream
            .read_exact(&mut response)
            .map_err(|error| format!("read: {error}"))?;
        black_box(response[0]);
        round_trips.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

fn run_lock_hog(args: LockHogArgs) -> Result<(), String> {
    if args.workers == 0 {
        return Err("workers must be greater than zero".to_string());
    }
    if args.workers == 1 {
        return Err("workers must be at least two for contention".to_string());
    }

    println!(
        "lock-hog pid: {} workers: {}",
        std::process::id(),
        args.workers,
    );

    // Leak the futex word so raw pointers handed to threads stay valid.
    let futex_word: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(0)));
    let acquisitions = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + args.duration;

    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let acquisitions = Arc::clone(&acquisitions);
        handles.push(
            thread::Builder::new()
                .name(format!("lock-hog-{worker}"))
                .spawn(move || lock_worker(futex_word, deadline, &acquisitions))
                .map_err(|error| format!("failed to spawn lock worker: {error}"))?,
        );
    }

    join_workers(handles)?;
    println!(
        "lock-hog: {} acquisitions",
        acquisitions.load(Ordering::Relaxed),
    );
    Ok(())
}

fn lock_worker(
    futex_word: &'static AtomicU32,
    deadline: Instant,
    acquisitions: &AtomicU64,
) -> Result<(), String> {
    let word = futex_word as *const AtomicU32 as *mut u32;
    let futex_wait = libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG;
    let futex_wake = libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG;
    let mut value = 0u64;

    while Instant::now() < deadline {
        // Acquire: spin once, then park in the kernel on the contended word.
        loop {
            match futex_word.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => break,
                Err(_) => unsafe {
                    // FUTEX_WAIT re-checks the value == 1 before parking, so
                    // a concurrent release wakes us with EAGAIN. The timeout
                    // argument must be passed explicitly: variadic syscall
                    // arguments left out are read as garbage by the kernel.
                    libc::syscall(
                        libc::SYS_futex,
                        word,
                        futex_wait,
                        1,
                        ptr::null::<libc::timespec>(),
                    );
                },
            }
        }

        // Critical section: brief busy work while holding the lock.
        value = value.wrapping_mul(31).wrapping_add(1);
        black_box(value);
        acquisitions.fetch_add(1, Ordering::Relaxed);

        // Release: wake every parked contender to keep the convoy hot.
        futex_word.store(0, Ordering::Release);
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                word,
                futex_wake,
                i32::MAX,
                ptr::null::<libc::timespec>(),
            );
        }
    }
    Ok(())
}

fn run_mem_hog(args: MemHogArgs) -> Result<(), String> {
    if args.workers == 0 {
        return Err("workers must be greater than zero".to_string());
    }
    if args.size_mib == 0 {
        return Err("size-mib must be greater than zero".to_string());
    }

    println!(
        "mem-hog pid: {} workers: {} size: {} MiB per round",
        std::process::id(),
        args.workers,
        args.size_mib,
    );

    let rounds = Arc::new(AtomicU64::new(0));
    let bytes_faulted = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + args.duration;
    let size = args.size_mib * 1024 * 1024;

    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let rounds = Arc::clone(&rounds);
        let bytes_faulted = Arc::clone(&bytes_faulted);
        handles.push(
            thread::Builder::new()
                .name(format!("mem-hog-{worker}"))
                .spawn(move || mem_worker(size, deadline, &rounds, &bytes_faulted))
                .map_err(|error| format!("failed to spawn mem worker: {error}"))?,
        );
    }

    join_workers(handles)?;
    println!(
        "mem-hog: {} rounds, {} MiB faulted",
        rounds.load(Ordering::Relaxed),
        bytes_faulted.load(Ordering::Relaxed) / (1024 * 1024),
    );
    Ok(())
}

fn mem_worker(size: usize, deadline: Instant, rounds: &AtomicU64, bytes_faulted: &AtomicU64) -> Result<(), String> {
    while Instant::now() < deadline {
        let region = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if region == libc::MAP_FAILED {
            return Err("mmap failed".to_string());
        }

        // Touch every page to force fresh page faults, then release the
        // mapping so the next round cannot reuse warm pages.
        let base = region.cast::<u8>();
        for page in (0..size).step_by(CHUNK_SIZE) {
            unsafe {
                base.add(page).write_volatile(1);
            }
        }

        if unsafe { libc::munmap(region, size) } != 0 {
            return Err("munmap failed".to_string());
        }

        rounds.fetch_add(1, Ordering::Relaxed);
        bytes_faulted.fetch_add(size as u64, Ordering::Relaxed);
    }
    Ok(())
}

fn join_workers(handles: Vec<thread::JoinHandle<Result<(), String>>>) -> Result<(), String> {
    for handle in handles {
        handle
            .join()
            .map_err(|_| "a worker panicked".to_string())??;
    }
    Ok(())
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let duration = humantime::parse_duration(value)
        .map_err(|error| format!("invalid duration `{value}`: {error}"))?;
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_string());
    }
    Ok(duration)
}
