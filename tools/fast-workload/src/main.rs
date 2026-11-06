use std::{
    alloc::{Layout, alloc, dealloc},
    collections::HashSet,
    fs::{File, OpenOptions},
    hint::black_box,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    ptr,
    sync::{
        Arc, Mutex,
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
    /// Repeatedly create and exit sleeping threads (validates TID cleanup).
    #[command(name = "thread-exit-hog")]
    ThreadExit(ThreadExitArgs),
    /// Allocation and page-fault churn (validates `fast memory`).
    #[command(name = "mem-hog")]
    Mem(MemHogArgs),
    /// Futex contention and real block I/O in one process (mixed bottleneck).
    #[command(name = "mixed-hog")]
    Mixed(MixedHogArgs),
    /// Adversarial TCP connection lifecycle (validates TCP ownership rules).
    #[command(name = "tcp-lifecycle")]
    TcpLifecycle(TcpLifecycleArgs),
}

#[derive(Debug, Clone, Args)]
struct CommonArgs {
    /// Write a machine-readable report here when the workload finishes.
    #[arg(long, value_name = "PATH")]
    report: Option<PathBuf>,
    /// Create this file once the workload is ready to be observed.
    #[arg(long, value_name = "PATH")]
    ready_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct IoHogArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of I/O worker threads.
    #[arg(long, default_value_t = 1)]
    workers: usize,

    /// File to read or write. Created (and overwritten) unless reuse-file is set.
    #[arg(long, default_value = "/tmp/fast-workload-io")]
    path: PathBuf,

    /// File size in MiB.
    #[arg(long, default_value_t = 64)]
    size_mib: u64,

    /// Read at random offsets instead of sequentially.
    #[arg(long)]
    random: bool,

    /// Repeatedly access sector zero; alternating workers read and write.
    #[arg(long)]
    same_sector: bool,

    /// Make all workers write instead of read.
    #[arg(long)]
    write: bool,

    /// Flush after each write to generate block flush requests.
    #[arg(long)]
    flush: bool,

    /// Reuse an existing file without truncating or rewriting it.
    #[arg(long)]
    reuse_file: bool,
}

struct IoWorkerArgs {
    path: PathBuf,
    file_size: u64,
    random: bool,
    same_sector: bool,
    write: bool,
    flush: bool,
    worker: usize,
    deadline: Instant,
    cursor: Arc<AtomicU64>,
    bytes_read: Arc<AtomicU64>,
    bytes_written: Arc<AtomicU64>,
    latencies: Arc<LatencySamples>,
}

#[derive(Debug, Clone, Args)]
struct NetHogArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of client threads, each with its own loopback connection.
    #[arg(long, default_value_t = 2)]
    workers: usize,

    /// Cycle the connection open and shut to force real retransmissions.
    ///
    /// A loopback link never loses packets, so a stalled reader alone is not
    /// enough: data sitting in the receive buffer is still acknowledged the
    /// moment it arrives. What does cause retransmission is a receive window
    /// that closes while segments are still in flight. This stops the server
    /// from reading, waits longer than the retransmission timeout for the
    /// sender to give up and resend, then drains and repeats.
    ///
    /// The value is the per-cycle stall in milliseconds and must exceed the
    /// kernel's 200ms initial RTO. 0 keeps the normal echo behaviour.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    delay_ms: u64,

    /// Server socket receive buffer in KiB, used only when cycling. A small
    /// buffer makes the advertised window close quickly, so segments are
    /// still in flight when it shuts and the sender has something to resend.
    #[arg(long, default_value_t = 8, value_name = "KB")]
    rcvbuf_kb: u64,

    /// Delay before the echo server replies, in milliseconds.
    ///
    /// This models a slow remote peer: the connection is healthy, but each
    /// request waits for the server. The client-side round-trip measurement
    /// is an independent reference for what the collector should see.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    peer_delay_ms: u64,
}

/// Address family for the lifecycle workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LifecycleFamily {
    Ipv4,
    Ipv6,
}

/// Adversarial connection lifecycle for the TCP ownership rules.
///
/// One run covers what the rules have to get right: connections that already
/// exist when collection attaches, connections created during collection,
/// IPv4 and IPv6, a reused 4-tuple, a server side whose handshake queue is
/// starved so a connect is genuinely slow, connects that fail, and a socket
/// handed to another process and closed here.
#[derive(Debug, Clone, Args)]
struct TcpLifecycleArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the workload should stay alive.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Loopback address family.
    #[arg(long, value_enum, default_value_t = LifecycleFamily::Ipv4)]
    family: LifecycleFamily,

    /// Connections opened one after another, each measured.
    #[arg(long, default_value_t = 6)]
    connects: u32,

    /// Wait this long between connections, so a collector that attaches a
    /// moment later still observes them being created.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    connect_interval_ms: u64,

    /// Stop accepting for this long before the last connect, so the listener's
    /// handshake queue is full and the kernel drops the SYN. The client then
    /// retransmits and the connect takes about a second.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    starve_ms: u64,

    /// Bind every client to one local port, so the same 4-tuple is opened,
    /// closed and opened again.
    #[arg(long, default_value_t = false)]
    reuse_tuple: bool,

    /// Connect this many times to a port with no listener.
    #[arg(long, default_value_t = 2)]
    failed_connects: u32,

    /// Hand the last connection to a forked child over SCM_RIGHTS and close it
    /// here, so this process no longer holds that socket.
    #[arg(long, default_value_t = false)]
    pass_fd: bool,

    /// Wait this long after the last connection before handing it over, so a
    /// collector attached in the meantime can see the descriptor first.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    pass_delay_ms: u64,
}

#[derive(Debug, Clone, Args)]
struct LockHogArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of threads contending on one futex word.
    #[arg(long, default_value_t = 4)]
    workers: usize,

    /// Optional time to sleep while holding the lock, in milliseconds.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    hold_ms: u64,
}

#[derive(Debug, Clone, Args)]
struct ThreadExitArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the churn workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of short-lived sleeping threads in each batch.
    #[arg(long, default_value_t = 64)]
    workers: usize,

    /// How long each worker sleeps before exiting, in milliseconds.
    #[arg(long, default_value_t = 200, value_name = "MS")]
    sleep_ms: u64,
}

#[derive(Debug, Clone, Args)]
struct MemHogArgs {
    #[command(flatten)]
    common: CommonArgs,

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

#[derive(Debug, Clone, Args)]
struct MixedHogArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// How long the workload should run.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Number of threads contending on one futex word.
    #[arg(long, default_value_t = 8)]
    workers: usize,

    /// Time to sleep while holding the lock, in milliseconds.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    hold_ms: u64,

    /// File the I/O workers read with O_DIRECT.
    #[arg(long, default_value = "/tmp/fast-workload-io")]
    path: PathBuf,

    /// File size in MiB.
    #[arg(long, default_value_t = 32)]
    size_mib: u64,

    /// Number of O_DIRECT reader threads in the same process.
    #[arg(long, default_value_t = 1)]
    io_workers: usize,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.mode {
        Mode::Io(args) => run_io_hog(args),
        Mode::Net(args) => run_net_hog(args),
        Mode::Lock(args) => run_lock_hog(args),
        Mode::ThreadExit(args) => run_thread_exit_hog(args),
        Mode::Mem(args) => run_mem_hog(args),
        Mode::Mixed(args) => run_mixed_hog(args),
        Mode::TcpLifecycle(args) => run_tcp_lifecycle(args),
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
    if args.same_sector && args.random {
        return Err("same-sector and random cannot be used together".to_string());
    }
    if args.flush && !(args.write || (args.same_sector && args.workers > 1)) {
        return Err("flush requires at least one write worker".to_string());
    }

    let file_size = args.size_mib * 1024 * 1024;
    if args.reuse_file {
        let metadata = std::fs::metadata(&args.path)
            .map_err(|error| format!("stat {}: {error}", args.path.display()))?;
        if metadata.len() < file_size {
            return Err(format!(
                "{} is {} bytes, shorter than requested {} bytes",
                args.path.display(),
                metadata.len(),
                file_size
            ));
        }
    } else {
        prepare_file(&args.path, file_size)?;
    }

    println!(
        "io-hog pid: {} file: {} size: {} MiB workers: {} pattern: {}",
        std::process::id(),
        args.path.display(),
        args.size_mib,
        args.workers,
        if args.same_sector {
            "same-sector"
        } else if args.random {
            "random"
        } else {
            "sequential"
        },
    );
    mark_ready(&args.common)?;

    let latencies = Arc::new(LatencySamples::default());
    let cursor = Arc::new(AtomicU64::new(0));
    let bytes_read = Arc::new(AtomicU64::new(0));
    let bytes_written = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + args.duration;
    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let write = args.write || (args.same_sector && worker % 2 == 1);
        let worker_args = IoWorkerArgs {
            path: args.path.clone(),
            file_size,
            random: args.random,
            same_sector: args.same_sector,
            write,
            flush: args.flush && write,
            worker,
            deadline,
            cursor: Arc::clone(&cursor),
            bytes_read: Arc::clone(&bytes_read),
            bytes_written: Arc::clone(&bytes_written),
            latencies: Arc::clone(&latencies),
        };
        handles.push(
            thread::Builder::new()
                .name(format!("io-hog-{worker}"))
                .spawn(move || io_worker(worker_args))
                .map_err(|error| format!("failed to spawn io worker: {error}"))?,
        );
    }

    join_workers(handles)?;
    let reads = bytes_read.load(Ordering::Relaxed) / CHUNK_SIZE as u64;
    let writes = bytes_written.load(Ordering::Relaxed) / CHUNK_SIZE as u64;
    if args.same_sector {
        println!("io-hog: completed {reads} reads and {writes} writes at sector zero");
    } else if args.write {
        println!(
            "io-hog: wrote {} bytes in {writes} writes",
            bytes_written.load(Ordering::Relaxed)
        );
    } else {
        println!(
            "io-hog: read {} bytes in {reads} reads",
            bytes_read.load(Ordering::Relaxed),
        );
    }
    write_report(
        &args.common,
        "io-hog",
        args.duration,
        reads + writes,
        latencies.percentiles(),
        &[("workers", args.workers as u64)],
    )?;
    Ok(())
}

fn prepare_file(path: &PathBuf, size: u64) -> Result<(), String> {
    let mut file =
        File::create(path).map_err(|error| format!("create {}: {error}", path.display()))?;
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

fn io_worker(args: IoWorkerArgs) -> Result<(), String> {
    let IoWorkerArgs {
        path,
        file_size,
        random,
        same_sector,
        write,
        flush,
        worker,
        deadline,
        cursor,
        bytes_read,
        bytes_written,
        latencies,
    } = args;
    let file = open_direct(&path, write)?;
    let fd = file.as_raw_fd();

    // O_DIRECT requires page-aligned buffers and offsets.
    let layout = Layout::from_size_align(CHUNK_SIZE, CHUNK_SIZE)
        .map_err(|error| format!("buffer layout: {error}"))?;
    let buffer = unsafe { alloc(layout) };
    if buffer.is_null() {
        return Err("failed to allocate the I/O buffer".to_string());
    }
    if write {
        unsafe { ptr::write_bytes(buffer, 0, CHUNK_SIZE) };
    }

    let mut seed = (worker as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15);
    let mut offset;
    let chunk = CHUNK_SIZE as u64;
    while Instant::now() < deadline {
        if same_sector {
            offset = 0;
        } else if random {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            // O_DIRECT requires sector-aligned offsets; keep I/O on chunk
            // boundaries.
            offset = (seed % (file_size / chunk)) * chunk;
        } else {
            offset = cursor.fetch_add(chunk, Ordering::Relaxed) % file_size;
        }

        let n = unsafe {
            let started = Instant::now();
            let result = if write {
                libc::pwrite(fd, buffer.cast(), CHUNK_SIZE, offset as libc::off_t)
            } else {
                libc::pread(fd, buffer.cast(), CHUNK_SIZE, offset as libc::off_t)
            };
            // The elapsed time includes the syscall only, not the flush, so
            // the report describes request service time rather than the
            // durability cost an unrelated signal would add.
            latencies.record(started.elapsed());
            result
        };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            unsafe { dealloc(buffer, layout) };
            return Err(format!("I/O at offset {offset}: {error}"));
        }
        if flush && unsafe { libc::fdatasync(fd) } < 0 {
            let error = std::io::Error::last_os_error();
            unsafe { dealloc(buffer, layout) };
            return Err(format!("fdatasync after write at offset {offset}: {error}"));
        }
        black_box(unsafe { buffer.read_volatile() });
        if write {
            bytes_written.fetch_add(n as u64, Ordering::Relaxed);
        } else {
            bytes_read.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    unsafe { dealloc(buffer, layout) };
    Ok(())
}

fn open_direct(path: &PathBuf, write: bool) -> Result<File, String> {
    match OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_DIRECT)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(direct_error) => {
            // tmpfs and some overlays reject O_DIRECT; fall back loudly.
            eprintln!(
                "warning: O_DIRECT unsupported on {} ({}); falling back to buffered I/O",
                path.display(),
                direct_error
            );
            let mut file = OpenOptions::new()
                .read(true)
                .write(write)
                .open(path)
                .map_err(|error| format!("open: {error}"))?;
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
        "net-hog pid: {} endpoint: 127.0.0.1:{port} workers: {} delay: {}ms peer-delay: {}ms",
        std::process::id(),
        args.workers,
        args.delay_ms,
        args.peer_delay_ms,
    );
    mark_ready(&args.common)?;

    let round_trips = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(LatencySamples::default());
    let deadline = Instant::now() + args.duration;
    let stalling = args.delay_ms > 0;
    let delay = Duration::from_millis(args.delay_ms);
    let peer_delay = Duration::from_millis(args.peer_delay_ms);
    let rcvbuf_kb = args.rcvbuf_kb;

    let server = thread::Builder::new()
        .name("net-hog-server".to_string())
        .spawn(move || echo_server(listener, deadline, delay, stalling, rcvbuf_kb, peer_delay))
        .map_err(|error| format!("failed to spawn server: {error}"))?;

    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let round_trips = Arc::clone(&round_trips);
        let sent = Arc::clone(&sent);
        let latencies = Arc::clone(&latencies);
        handles.push(
            thread::Builder::new()
                .name(format!("net-hog-client-{worker}"))
                .spawn(move || {
                    if stalling {
                        net_client_stall(port, deadline, &sent)
                    } else {
                        net_client(port, deadline, &round_trips, &latencies)
                    }
                })
                .map_err(|error| format!("failed to spawn client: {error}"))?,
        );
    }

    join_workers(handles)?;
    // Give the server a moment to drain and exit.
    let _ = server.join();
    if stalling {
        println!(
            "net-hog: {} bytes written with a {}ms server delay, expecting retransmissions",
            sent.load(Ordering::Relaxed),
            args.delay_ms,
        );
    } else {
        println!(
            "net-hog: {} round trips over {port}",
            round_trips.load(Ordering::Relaxed),
        );
    }
    write_report(
        &args.common,
        "net-hog",
        args.duration,
        if stalling {
            sent.load(Ordering::Relaxed)
        } else {
            round_trips.load(Ordering::Relaxed)
        },
        latencies.percentiles(),
        &[
            ("workers", args.workers as u64),
            ("peer_delay_ms", args.peer_delay_ms),
        ],
    )?;
    Ok(())
}

fn echo_server(
    listener: std::net::TcpListener,
    deadline: Instant,
    delay: Duration,
    stalling: bool,
    rcvbuf_kb: u64,
    peer_delay: Duration,
) {
    let _ = listener.set_nonblocking(true);
    while Instant::now() < deadline + Duration::from_secs(1) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = thread::Builder::new()
                    .name("net-hog-echo".to_string())
                    .spawn(move || echo_connection(stream, delay, stalling, rcvbuf_kb, peer_delay));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

/// Echoes until the peer goes away, or cycles the receive window shut and
/// open again when a stall was requested.
fn echo_connection(
    mut stream: std::net::TcpStream,
    delay: Duration,
    stalling: bool,
    rcvbuf_kb: u64,
    peer_delay: Duration,
) {
    let mut buffer = [0u8; 1024];
    if !stalling {
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if !peer_delay.is_zero() {
                        // Deliberate remote-side think time: the connection is
                        // healthy, so this is a slow peer rather than loss.
                        thread::sleep(peer_delay);
                    }
                    if stream.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        return;
    }

    // A small receive buffer closes the advertised window quickly, so the
    // sender still has segments in flight when the window shuts.
    let size = (rcvbuf_kb as libc::c_int).saturating_mul(1024);
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));

    // Each pass drains what has arrived, then stops reading for long enough
    // that the sender's retransmission timer expires. The drain reopens the
    // window, so the cycle repeats for as long as the fixture runs and
    // produces a fresh burst of retransmissions every pass.
    let horizon = Instant::now() + Duration::from_secs(120);
    while Instant::now() < horizon {
        let mut reads = 0;
        while reads < 16 {
            match stream.read(&mut buffer) {
                Ok(0) => return,
                Ok(n) => {
                    reads += 1;
                    if stream.write_all(&buffer[..n]).is_err() {
                        return;
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => return,
            }
        }
        // The stall is the part that matters: no reads happen here, so the
        // receive buffer fills, the advertised window shuts, and whatever the
        // sender still has unacknowledged gets resent.
        thread::sleep(delay);
    }
}

/// Writes continuously without waiting for replies, so the peer's receive
/// window closes and its retransmission timer fires.
fn net_client_stall(port: u16, deadline: Instant, sent: &AtomicU64) -> Result<(), String> {
    let stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .map_err(|error| format!("connect 127.0.0.1:{port}: {error}"))?;
    let _ = stream.set_nodelay(true);
    // A short write timeout makes each blocked write return periodically, so
    // the deadline is still honoured and the fixture exits on its own instead
    // of hanging until it is killed.
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    let mut stream = stream;
    let payload = [0x5Au8; 4096];
    while Instant::now() < deadline {
        // write_all blocks once the send buffer fills, which is exactly the
        // backpressure needed for the unacknowledged data to accumulate. A
        // timeout on the blocked socket is expected and not a failure.
        if let Err(error) = stream.write_all(&payload)
            && error.kind() != std::io::ErrorKind::WouldBlock
            && error.kind() != std::io::ErrorKind::TimedOut
        {
            return Err(format!("write: {error}"));
        }
        sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
    }
    Ok(())
}

fn net_client(
    port: u16,
    deadline: Instant,
    round_trips: &AtomicU64,
    latencies: &LatencySamples,
) -> Result<(), String> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .map_err(|error| format!("connect 127.0.0.1:{port}: {error}"))?;
    let _ = stream.set_nodelay(true);

    let mut request = [0u8; 256];
    for (i, byte) in request.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let mut response = [0u8; 256];

    while Instant::now() < deadline {
        let started = Instant::now();
        stream
            .write_all(&request)
            .map_err(|error| format!("write: {error}"))?;
        stream
            .read_exact(&mut response)
            .map_err(|error| format!("read: {error}"))?;
        latencies.record(started.elapsed());
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
    let latencies = Arc::new(LatencySamples::default());
    let deadline = Instant::now() + args.duration;
    let hold = Duration::from_millis(args.hold_ms);
    mark_ready(&args.common)?;

    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let acquisitions = Arc::clone(&acquisitions);
        let latencies = Arc::clone(&latencies);
        handles.push(
            thread::Builder::new()
                .name(format!("lock-hog-{worker}"))
                .spawn(move || lock_worker(futex_word, deadline, hold, &acquisitions, &latencies))
                .map_err(|error| format!("failed to spawn lock worker: {error}"))?,
        );
    }

    join_workers(handles)?;
    println!(
        "lock-hog: {} acquisitions",
        acquisitions.load(Ordering::Relaxed),
    );
    write_report(
        &args.common,
        "lock-hog",
        args.duration,
        acquisitions.load(Ordering::Relaxed),
        latencies.percentiles(),
        &[("workers", args.workers as u64), ("hold_ms", args.hold_ms)],
    )?;
    Ok(())
}

fn run_thread_exit_hog(args: ThreadExitArgs) -> Result<(), String> {
    if args.workers == 0 {
        return Err("workers must be greater than zero".to_string());
    }
    if args.sleep_ms == 0 {
        return Err("sleep-ms must be greater than zero".to_string());
    }

    let seen_tids = Arc::new(Mutex::new(HashSet::new()));
    let created = Arc::new(AtomicU64::new(0));
    let reused = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + args.duration;
    let sleep = Duration::from_millis(args.sleep_ms);
    mark_ready(&args.common)?;

    while Instant::now() < deadline {
        let mut handles = Vec::with_capacity(args.workers);
        for worker in 0..args.workers {
            let seen_tids = Arc::clone(&seen_tids);
            let created = Arc::clone(&created);
            let reused = Arc::clone(&reused);
            handles.push(
                thread::Builder::new()
                    .name(format!("thread-exit-{worker}"))
                    .spawn(move || {
                        let tid = u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) })
                            .map_err(|error| format!("gettid returned an invalid id: {error}"))?;
                        created.fetch_add(1, Ordering::Relaxed);
                        let mut seen = seen_tids
                            .lock()
                            .map_err(|_| "TID reuse tracker was poisoned".to_string())?;
                        if !seen.insert(tid) {
                            reused.fetch_add(1, Ordering::Relaxed);
                        }
                        drop(seen);
                        thread::sleep(sleep);
                        Ok(())
                    })
                    .map_err(|error| format!("failed to spawn exit worker: {error}"))?,
            );
        }
        join_workers(handles)?;
    }

    println!(
        "thread-exit-hog: created {} threads, reused {} TIDs",
        created.load(Ordering::Relaxed),
        reused.load(Ordering::Relaxed)
    );
    write_report(
        &args.common,
        "thread-exit-hog",
        args.duration,
        created.load(Ordering::Relaxed),
        None,
        &[("reused_tids", reused.load(Ordering::Relaxed))],
    )?;
    Ok(())
}

fn lock_worker(
    futex_word: &'static AtomicU32,
    deadline: Instant,
    hold: Duration,
    acquisitions: &AtomicU64,
    latencies: &LatencySamples,
) -> Result<(), String> {
    let word = futex_word as *const AtomicU32 as *mut u32;
    let futex_wait = libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG;
    let futex_wake = libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG;
    let mut value = 0u64;

    while Instant::now() < deadline {
        // Acquire: spin once, then park in the kernel on the contended word.
        // The time from here to the successful exchange is the wait the
        // collector should see, independently of its own off-CPU accounting.
        let wait_started = Instant::now();
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
        latencies.record(wait_started.elapsed());

        // Optional hold time makes a deliberate lock bottleneck rank ahead of
        // CPU use in deterministic diagnostic scenarios.
        if !hold.is_zero() {
            thread::sleep(hold);
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
    mark_ready(&args.common)?;

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
    write_report(
        &args.common,
        "mem-hog",
        args.duration,
        rounds.load(Ordering::Relaxed),
        None,
        &[
            ("workers", args.workers as u64),
            ("bytes_faulted", bytes_faulted.load(Ordering::Relaxed)),
        ],
    )?;
    Ok(())
}

fn run_mixed_hog(args: MixedHogArgs) -> Result<(), String> {
    if args.workers < 2 {
        return Err("workers must be at least two for contention".to_string());
    }
    if args.io_workers == 0 {
        return Err("io-workers must be greater than zero".to_string());
    }
    if args.size_mib == 0 {
        return Err("size-mib must be greater than zero".to_string());
    }

    let file_size = args.size_mib * 1024 * 1024;
    prepare_file(&args.path, file_size)?;
    println!(
        "mixed-hog pid: {} file: {} lock-workers: {} io-workers: {}",
        std::process::id(),
        args.path.display(),
        args.workers,
        args.io_workers,
    );

    let futex_word: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(0)));
    let acquisitions = Arc::new(AtomicU64::new(0));
    let lock_latencies = Arc::new(LatencySamples::default());
    let bytes_read = Arc::new(AtomicU64::new(0));
    let bytes_written = Arc::new(AtomicU64::new(0));
    let cursor = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + args.duration;
    let hold = Duration::from_millis(args.hold_ms);

    let mut handles = Vec::with_capacity(args.workers + args.io_workers);
    for worker in 0..args.workers {
        let acquisitions = Arc::clone(&acquisitions);
        let latencies = Arc::clone(&lock_latencies);
        handles.push(
            thread::Builder::new()
                .name(format!("mixed-lock-{worker}"))
                .spawn(move || lock_worker(futex_word, deadline, hold, &acquisitions, &latencies))
                .map_err(|error| format!("failed to spawn lock worker: {error}"))?,
        );
    }
    for worker in 0..args.io_workers {
        let worker_args = IoWorkerArgs {
            path: args.path.clone(),
            file_size,
            random: true,
            same_sector: false,
            write: false,
            flush: false,
            worker,
            deadline,
            cursor: Arc::clone(&cursor),
            bytes_read: Arc::clone(&bytes_read),
            bytes_written: Arc::clone(&bytes_written),
            latencies: Arc::new(LatencySamples::default()),
        };
        handles.push(
            thread::Builder::new()
                .name(format!("mixed-io-{worker}"))
                .spawn(move || io_worker(worker_args))
                .map_err(|error| format!("failed to spawn io worker: {error}"))?,
        );
    }
    mark_ready(&args.common)?;

    join_workers(handles)?;
    let reads = bytes_read.load(Ordering::Relaxed) / CHUNK_SIZE as u64;
    write_report(
        &args.common,
        "mixed-hog",
        args.duration,
        acquisitions.load(Ordering::Relaxed) + reads,
        lock_latencies.percentiles(),
        &[
            ("workers", args.workers as u64),
            ("io_workers", args.io_workers as u64),
            ("io_reads", reads),
        ],
    )?;
    Ok(())
}

fn mem_worker(
    size: usize,
    deadline: Instant,
    rounds: &AtomicU64,
    bytes_faulted: &AtomicU64,
) -> Result<(), String> {
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

/// Upper bound on retained latency samples per fixture.
///
/// A 30s run at tens of thousands of operations per second would otherwise
/// accumulate millions of samples and distort the memory signal the fixture is
/// supposed to produce. The first samples are kept rather than a random
/// sample, so the report is deterministic for a deterministic workload.
const MAX_LATENCY_SAMPLES: usize = 200_000;

/// Latency samples shared by the worker threads.
#[derive(Default)]
struct LatencySamples {
    samples: Mutex<Vec<u32>>,
}

impl LatencySamples {
    fn record(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u32::MAX as u128) as u32;
        if let Ok(mut samples) = self.samples.lock()
            && samples.len() < MAX_LATENCY_SAMPLES
        {
            samples.push(micros);
        }
    }

    fn percentiles(&self) -> Option<(u32, u32, u32)> {
        let mut samples = self.samples.lock().ok()?.clone();
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable();
        Some((
            percentile(&samples, 50),
            percentile(&samples, 95),
            percentile(&samples, 99),
        ))
    }
}

/// Nearest-rank percentile over an ascending slice.
fn percentile(sorted: &[u32], pct: usize) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

/// Creates the readiness marker the QEMU matrix waits for instead of sleeping.
fn mark_ready(common: &CommonArgs) -> Result<(), String> {
    if let Some(path) = &common.ready_file {
        std::fs::write(path, b"ready\n")
            .map_err(|error| format!("write {}: {error}", path.display()))?;
    }
    Ok(())
}

/// Writes the machine-readable reference measurement for this run.
///
/// The report is written by the fixture, not by the collector, so it is an
/// independent record of what the workload actually did. It is only written
/// after a normal finish, which keeps a killed run from looking measured.
fn write_report(
    common: &CommonArgs,
    workload: &str,
    duration: Duration,
    ops: u64,
    latency: Option<(u32, u32, u32)>,
    extra: &[(&str, u64)],
) -> Result<(), String> {
    let Some(path) = &common.report else {
        return Ok(());
    };
    let mut body = format!(
        "{{\"workload\":\"{workload}\",\"pid\":{},\"duration_ms\":{},\"ops\":{ops}",
        std::process::id(),
        duration.as_millis()
    );
    if let Some((p50, p95, p99)) = latency {
        body.push_str(&format!(
            ",\"latency_us\":{{\"p50\":{p50},\"p95\":{p95},\"p99\":{p99}}}"
        ));
    }
    for (name, value) in extra {
        body.push_str(&format!(",\"{name}\":{value}"));
    }
    body.push_str("}\n");
    std::fs::write(path, body).map_err(|error| format!("write {}: {error}", path.display()))
}

// --- TCP lifecycle workload -------------------------------------------------

/// Runs the adversarial TCP lifecycle.
///
/// Everything is on loopback, so no external network is required and the run
/// is reproducible inside the QEMU guest.
fn run_tcp_lifecycle(args: TcpLifecycleArgs) -> Result<(), String> {
    if args.connects == 0 {
        return Err("connects must be greater than zero".to_string());
    }
    let (bind_addr, connect_host) = match args.family {
        LifecycleFamily::Ipv4 => ("127.0.0.1:0", "127.0.0.1"),
        LifecycleFamily::Ipv6 => ("[::1]:0", "::1"),
    };
    let listener = std::net::TcpListener::bind(bind_addr)
        .map_err(|error| format!("bind {bind_addr}: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("local addr: {error}"))?
        .port();
    // A short backlog is what makes a starved handshake possible: the kernel
    // completes one connection and drops further SYNs until the queue drains.
    // Zero backlog: one unaccepted connection already fills the accept queue,
    // so the next SYN is dropped and the client retransmits.
    set_backlog(listener.as_raw_fd(), 0)?;

    println!(
        "tcp-lifecycle pid: {} listener: {connect_host}:{port} family {:?} connects: {} reuse-tuple: {} starve-ms: {} failed-connects: {} pass-fd: {}",
        std::process::id(),
        args.family,
        args.connects,
        args.reuse_tuple,
        args.starve_ms,
        args.failed_connects,
        args.pass_fd,
    );
    mark_ready(&args.common)?;

    // Forked before any worker thread exists: a child of a threaded process
    // may only call async-signal-safe functions, and this one has to receive
    // a descriptor and sleep.
    let mut handoff = if args.pass_fd {
        let holder = FdHolder::spawn()?;
        // Printed so a test can check that the descriptor really lives in
        // another process after the hand-off.
        println!("tcp-lifecycle: fd holder pid: {}", holder.pid);
        Some(holder)
    } else {
        None
    };

    let deadline = Instant::now() + args.duration;
    let accept_gate = Arc::new(AtomicU32::new(1));
    let server = {
        let accept_gate = Arc::clone(&accept_gate);
        thread::Builder::new()
            .name("tcp-lifecycle-server".to_string())
            .spawn(move || echo_until(listener, deadline, accept_gate))
            .map_err(|error| format!("failed to spawn server: {error}"))?
    };

    let mut connect_us = Vec::new();
    let mut failures = 0u32;
    let mut filler: Option<std::net::TcpStream> = None;
    let local_base = 40_000u16 + (std::process::id() as u16 % 1000);
    for index in 0..args.connects {
        if args.starve_ms > 0 && index + 1 == args.connects {
            // Fill the single accept slot and stop accepting, so the next
            // connect's SYN is dropped and the client retransmits after the
            // kernel's retransmission timeout instead of completing at once.
            // The gate reopens on a timer, not after the connect returns:
            // waiting for the connect would deadlock against the full queue.
            accept_gate.store(0, Ordering::Relaxed);
            match connect_loopback(connect_host, port, None, false) {
                Ok((stream, _)) => filler = Some(stream),
                Err(error) => eprintln!("tcp-lifecycle: filler connect failed: {error}"),
            }
            let gate = Arc::clone(&accept_gate);
            let reopen_after = Duration::from_millis(args.starve_ms);
            thread::Builder::new()
                .name("tcp-lifecycle-gate".to_string())
                .spawn(move || {
                    thread::sleep(reopen_after);
                    gate.store(1, Ordering::Relaxed);
                })
                .map_err(|error| format!("failed to spawn gate timer: {error}"))?;
        }
        let reuse = args.reuse_tuple.then_some(local_base + index as u16);
        match connect_loopback(connect_host, port, reuse, args.reuse_tuple) {
            Ok((stream, micros)) => {
                connect_us.push(micros);
                let _ = echo_once(&stream);
                if args.pass_fd
                    && index + 1 == args.connects
                    && let Some(child) = handoff.as_mut()
                {
                    thread::sleep(Duration::from_millis(args.pass_delay_ms));
                    child.give(&stream)?;
                }
                drop(stream);
            }
            Err(error) => {
                eprintln!("tcp-lifecycle: connect {index} failed: {error}");
                failures += 1;
            }
        }
        accept_gate.store(1, Ordering::Relaxed);
        if args.connect_interval_ms > 0 && index + 1 < args.connects {
            thread::sleep(Duration::from_millis(args.connect_interval_ms));
        }
    }
    drop(filler);

    for _ in 0..args.failed_connects {
        match connect_loopback(connect_host, CLOSED_PORT, None, false) {
            Ok(_) => failures += 1,
            Err(_) => failures += 1,
        }
    }

    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let _ = server.join();
    if let Some(child) = handoff {
        child.stop();
    }

    let (p50, p95, p99) = percentiles(&connect_us);
    println!(
        "tcp-lifecycle: {} connection(s), {failures} failed, connect p50 {p50}us p95 {p95}us p99 {p99}us",
        connect_us.len()
    );
    write_report(
        &args.common,
        "tcp-lifecycle",
        args.duration,
        connect_us.len() as u64,
        Some((p50, p95, p99)),
        &[
            ("failed_connects", u64::from(failures)),
            ("reused_local_port", u64::from(args.reuse_tuple)),
        ],
    )
}

/// A loopback port with no listener, used to produce a failed connect.
const CLOSED_PORT: u16 = 1;

fn set_backlog(fd: std::os::fd::RawFd, backlog: i32) -> Result<(), String> {
    if unsafe { libc::listen(fd, backlog) } != 0 {
        return Err(format!(
            "listen({backlog}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_socket_flag(
    fd: std::os::fd::RawFd,
    level: i32,
    name: i32,
    value: i32,
) -> Result<(), String> {
    let value = value as libc::c_int;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "setsockopt({name}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Encodes a socket address as the kernel's `sockaddr` structure.
fn sockaddr_bytes(target: &str) -> Result<(Vec<u8>, libc::socklen_t), String> {
    use std::net::ToSocketAddrs;
    let address = target
        .to_socket_addrs()
        .map_err(|error| format!("resolve {target}: {error}"))?
        .next()
        .ok_or_else(|| format!("resolve {target}: no address"))?;
    match address {
        std::net::SocketAddr::V4(v4) => {
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = v4.port().to_be();
            raw.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            let length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let bytes = unsafe {
                std::slice::from_raw_parts(&raw as *const _ as *const u8, length as usize)
            }
            .to_vec();
            Ok((bytes, length))
        }
        std::net::SocketAddr::V6(v6) => {
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = v6.port().to_be();
            raw.sin6_addr.s6_addr = v6.ip().octets();
            let length = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let bytes = unsafe {
                std::slice::from_raw_parts(&raw as *const _ as *const u8, length as usize)
            }
            .to_vec();
            Ok((bytes, length))
        }
    }
}

/// Opens one loopback connection and measures how long the handshake took.
///
/// The socket is created through libc rather than `TcpStream::connect` because
/// the workload has to bind a specific local port to reuse a 4-tuple, and has
/// to disable lingering so the port is free again immediately.
fn connect_loopback(
    host: &str,
    port: u16,
    local_port: Option<u16>,
    reset_on_close: bool,
) -> Result<(std::net::TcpStream, u32), String> {
    use std::os::fd::FromRawFd;
    let family = if host.contains(':') {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    let result = (|| {
        set_socket_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        if reset_on_close {
            // Closing with SO_LINGER 0 sends RST, so the local port is not
            // held in TIME_WAIT and the same 4-tuple can be opened again.
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(format!("SO_LINGER: {}", std::io::Error::last_os_error()));
            }
        }
        if let Some(local_port) = local_port {
            let local = format!(
                "{}:{local_port}",
                if family == libc::AF_INET6 {
                    "[::1]"
                } else {
                    "127.0.0.1"
                }
            );
            let (bytes, length) = sockaddr_bytes(&local)?;
            if unsafe { libc::bind(fd, bytes.as_ptr().cast(), length) } != 0 {
                return Err(format!("bind {local}: {}", std::io::Error::last_os_error()));
            }
        }
        let (bytes, length) = sockaddr_bytes(&format!("{host}:{port}"))?;
        let started = Instant::now();
        let rc = unsafe { libc::connect(fd, bytes.as_ptr().cast(), length) };
        let elapsed = started.elapsed();
        if rc != 0 {
            return Err(format!(
                "connect {host}:{port}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok((
            unsafe { std::net::TcpStream::from_raw_fd(fd) },
            u32::try_from(elapsed.as_micros()).unwrap_or(u32::MAX),
        ))
    })();
    if result.is_err() {
        unsafe { libc::close(fd) };
    }
    result
}

fn echo_once(stream: &std::net::TcpStream) -> Result<(), String> {
    use std::io::{Read, Write};
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut stream_ref = stream;
    stream_ref
        .write_all(b"x")
        .map_err(|error| format!("write: {error}"))?;
    let mut byte = [0u8; 1];
    stream_ref
        .read_exact(&mut byte)
        .map_err(|error| format!("read: {error}"))
}

fn echo_until(listener: std::net::TcpListener, deadline: Instant, gate: Arc<AtomicU32>) {
    use std::io::{Read, Write};
    let _ = listener.set_nonblocking(true);
    let mut held = Vec::new();
    while Instant::now() < deadline {
        if gate.load(Ordering::Relaxed) == 0 {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut byte = [0u8; 1];
                if stream.read_exact(&mut byte).is_ok() {
                    let _ = stream.write_all(&byte);
                }
                held.push(stream);
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn percentiles(samples: &[u32]) -> (u32, u32, u32) {
    if samples.is_empty() {
        return (0, 0, 0);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let pick = |percent: f64| -> u32 {
        let index = ((percent / 100.0) * sorted.len() as f64).ceil() as usize;
        sorted[index.saturating_sub(1).min(sorted.len() - 1)]
    };
    (pick(50.0), pick(95.0), pick(99.0))
}

/// A forked child that holds one descriptor handed over with SCM_RIGHTS.
///
/// The child is forked before the workload starts its worker thread, so it
/// never inherits the observed connection; it only holds what it is given.
struct FdHolder {
    pid: libc::pid_t,
    channel: std::os::unix::net::UnixStream,
}

impl FdHolder {
    fn spawn() -> Result<Self, String> {
        let (parent, mut child) = std::os::unix::net::UnixStream::pair()
            .map_err(|error| format!("socketpair: {error}"))?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", std::io::Error::last_os_error()));
        }
        if pid == 0 {
            // Child: only syscalls and no allocation. Receive one descriptor,
            // hold it, and wait for the parent to close the channel.
            drop(parent);
            let fd = child_receive_fd(child.as_raw_fd());
            let mut sink = [0u8; 1];
            let _ = child.read(&mut sink);
            if let Some(fd) = fd {
                unsafe { libc::close(fd) };
            }
            unsafe { libc::_exit(0) };
        }
        drop(child);
        Ok(Self {
            pid,
            channel: parent,
        })
    }

    fn give(&mut self, stream: &std::net::TcpStream) -> Result<(), String> {
        send_fd(self.channel.as_raw_fd(), stream.as_raw_fd())
            .map_err(|error| format!("send fd: {error}"))
    }

    fn stop(self) {
        // Closing the channel wakes the child; the kill is a backstop for a
        // child that is still sleeping, so no orphan outlives the workload.
        let _ = unsafe { libc::kill(self.pid, libc::SIGTERM) };
        let mut status = 0;
        let _ = unsafe { libc::waitpid(self.pid, &mut status, 0) };
    }
}

fn send_fd(channel: std::os::fd::RawFd, fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(std::io::Error::other("no control message header"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            (&fd as *const libc::c_int).cast::<u8>(),
            libc::CMSG_DATA(header),
            std::mem::size_of::<libc::c_int>(),
        );
        message.msg_controllen = (*header).cmsg_len;
        let sent = libc::sendmsg(channel, &message, 0);
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receives one descriptor; used only in the forked child.
fn child_receive_fd(channel: std::os::fd::RawFd) -> Option<std::os::fd::RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut control = [0u8; 64];
    if space > control.len() {
        return None;
    }
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let received = unsafe { libc::recvmsg(channel, &mut message, 0) };
    if received <= 0 || message.msg_controllen == 0 {
        return None;
    }
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return None;
        }
        if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }
        let mut fd: libc::c_int = 0;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(header),
            (&mut fd as *mut libc::c_int).cast::<u8>(),
            std::mem::size_of::<libc::c_int>(),
        );
        Some(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_nearest_rank() {
        let values = [1, 2, 3, 4];
        assert_eq!(percentile(&values, 50), 2);
        assert_eq!(percentile(&values, 95), 4);
        assert_eq!(percentile(&values, 0), 1);
        assert_eq!(percentile(&[], 95), 0);
    }

    #[test]
    fn latency_samples_report_p50_p95_p99() {
        let samples = LatencySamples::default();
        for value in [1u32, 2, 3, 4, 100] {
            samples.record(Duration::from_micros(value as u64));
        }
        assert_eq!(samples.percentiles(), Some((3, 100, 100)));
    }
}
