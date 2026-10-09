//! Parallel whole-disk enumeration.
//!
//! macOS uses getattrlistbulk(2): one syscall returns hundreds of entries
//! with name, type, size, mtime and flags already attached, so there is no
//! per-file stat. Linux has no bulk-stat call, so this port uses
//! readdir(3) + fstatat(2): one stat per entry. Directories fan out over a
//! rayon pool; mount points are not crossed (a directory on a different
//! device gets FLAG_MOUNT and is not descended into).
//!
//! Children are opened with openat() relative to the parent's fd, so paths
//! never get rebuilt and PATH_MAX never bites.

use rayon::Scope;
use std::ffi::CString;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

pub const NONE: u32 = u32::MAX;

/// Folders never to open: set when the daemon runs without Full Disk
/// Access, where opening a consent-gated folder (Downloads, Desktop, ...)
/// pops a privacy prompt and blocks the call until someone answers it.
pub static SKIP: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();

/// Mount points to descend into anyway. On macOS the data volume appears
/// under / via firmlinks, which the walker crosses; on Linux the user's
/// home is typically a separate mount, so it is listed here to get the
/// same "home appears under / exactly once" tree shape.
pub static DESCEND: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();

pub fn blocked(path: &[u8]) -> bool {
    SKIP.get().is_some_and(|v| v.iter().any(|s| path.starts_with(s) && (path.len() == s.len() || path[s.len()] == b'/')))
}

fn force_descend(path: &[u8]) -> bool {
    DESCEND.get().is_some_and(|v| v.iter().any(|s| s == path))
}

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_LINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;

/// Entry flag bit: hidden file. macOS uses the Finder UF_HIDDEN flag;
/// on Linux a leading dot marks hidden.
pub const FLAG_HIDDEN: u8 = 1 << 2;
/// Directory that is a mount point we did not descend into.
pub const FLAG_MOUNT: u8 = 1 << 3;

#[derive(Clone, Copy)]
pub struct RawEnt {
    pub name_off: u32,
    pub name_len: u16,
    /// kind in the low 2 bits, FLAG_* above.
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
    /// Temp id of the listing for this directory, or NONE.
    pub child: u32,
}

pub struct Listing {
    pub id: u32,
    pub names: Vec<u8>,
    pub ents: Vec<RawEnt>,
}

struct Ctx {
    next_id: AtomicU32,
    out: Vec<Mutex<Vec<Listing>>>,
}

/// Scan `root` recursively. Listing id 0 is `root` itself.
pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).start_handler(|_| crate::no_materialize()).build().unwrap();
    let ctx = Ctx { next_id: AtomicU32::new(1), out: (0..threads + 1).map(|_| Mutex::new(Vec::new())).collect() };
    raise_fd_limit();
    let fd = if blocked(root) { -1 } else { CString::new(root).map_or(-1, |c| unsafe { libc::open(c.as_ptr(), OPEN_DIR) }) };
    // Paths are only tracked when there is something to skip or force-descend.
    let path = (SKIP.get().is_some_and(|v| !v.is_empty()) || DESCEND.get().is_some_and(|v| !v.is_empty())).then(|| root.to_vec());
    pool.scope(|s| finish_dir(s, fd, path, 0, &ctx));
    ctx.out.into_iter().flat_map(|m| m.into_inner().unwrap()).collect()
}

fn raise_fd_limit() {
    let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) };
    r.rlim_cur = r.rlim_max.min(65536);
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) };
}

/// List a single directory (no recursion). Subdirectories come back with
/// `child == NONE`. Used by the live updater.
pub fn list_one(path: &[u8]) -> Option<Listing> {
    if blocked(path) {
        return None;
    }
    let mut l = Listing { id: 0, names: Vec::new(), ents: Vec::new() };
    list_into(path, &mut l).then_some(l)
}

const OPEN_DIR: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Directory fd shared by the tasks that still need to openat() a child.
struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// Children are opened with openat() relative to the parent's fd, so paths
// never get rebuilt and PATH_MAX never bites.
fn finish_dir<'s>(s: &Scope<'s>, fd: i32, path: Option<Vec<u8>>, id: u32, ctx: &'s Ctx) {
    let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
    if fd < 0 {
        push(l, ctx);
        return;
    }
    list_fd(fd, &mut l);
    let me = std::sync::Arc::new(Fd(fd));
    let mut kids = Vec::new();
    for e in l.ents.iter_mut() {
        if e.kind & 3 == KIND_DIR {
            let name = &l.names[e.name_off as usize..e.name_off as usize + e.name_len as usize];
            let child_path = path.as_ref().map(|p| crate::live::join(p, name));
            if child_path.as_deref().is_some_and(blocked) {
                continue;
            }
            // Mount points are not crossed, unless explicitly listed in
            // DESCEND (e.g. the user's home on Linux).
            if e.kind & FLAG_MOUNT != 0 && !child_path.as_deref().is_some_and(force_descend) {
                continue;
            }
            e.child = ctx.next_id.fetch_add(1, Ordering::Relaxed);
            kids.push((CString::new(name).unwrap_or_default(), e.child, child_path));
        }
    }
    push(l, ctx);
    for (name, cid, child_path) in kids {
        let parent = me.clone();
        s.spawn(move |s| {
            let fd = unsafe { libc::openat(parent.0, name.as_ptr(), OPEN_DIR) };
            drop(parent);
            finish_dir(s, fd, child_path, cid, ctx);
        });
    }
}

fn push(l: Listing, ctx: &Ctx) {
    let slot = rayon::current_thread_index().unwrap_or(ctx.out.len() - 1);
    ctx.out[slot].lock().unwrap().push(l);
}

/// Returns false if the directory could not be opened.
fn list_into(path: &[u8], l: &mut Listing) -> bool {
    let Ok(cpath) = CString::new(path) else { return false };
    let fd = unsafe { libc::open(cpath.as_ptr(), OPEN_DIR) };
    if fd < 0 {
        return false;
    }
    list_fd(fd, l);
    unsafe { libc::close(fd) };
    true
}

/// Fill `l` with one directory's entries via readdir(3) + fstatat(2).
///
/// Linux has no bulk-stat call, so each entry costs one fstatat; the stat
/// gives the authoritative type, size and mtime. Mount points are not
/// crossed: a directory on a different device than its parent gets
/// FLAG_MOUNT and `finish_dir` will not descend into it. Unlike
/// getattrlistbulk, readdir returns "." and "..", which are skipped here.
fn list_fd(fd: i32, l: &mut Listing) {
    let mut pst: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut pst) } != 0 {
        return;
    }
    let parent_dev = pst.st_dev;
    // fdopendir takes ownership of its fd; dup so the caller's fd stays
    // valid for the openat() calls that open children later.
    let dfd = unsafe { libc::dup(fd) };
    if dfd < 0 {
        return;
    }
    let dir = unsafe { libc::fdopendir(dfd) };
    if dir.is_null() {
        unsafe { libc::close(dfd) };
        return;
    }
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let dent = unsafe { libc::readdir(dir) };
        if dent.is_null() {
            break;
        }
        // Copy the name out: it is only valid until the next readdir.
        let name: Vec<u8> = unsafe { std::ffi::CStr::from_ptr((*dent).d_name.as_ptr()) }.to_bytes().to_vec();
        if name.is_empty() || name == b"." || name == b".." || name.len() > u16::MAX as usize {
            continue;
        }
        let Ok(cname) = CString::new(&name[..]) else { continue };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(fd, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            continue;
        }
        let mut kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => KIND_FILE,
            libc::S_IFDIR => KIND_DIR,
            libc::S_IFLNK => KIND_LINK,
            _ => KIND_OTHER,
        };
        if name[0] == b'.' {
            kind |= FLAG_HIDDEN;
        }
        if kind & 3 == KIND_DIR && st.st_dev != parent_dev {
            kind |= FLAG_MOUNT;
        }
        l.ents.push(RawEnt {
            name_off: l.names.len() as u32,
            name_len: name.len() as u16,
            kind,
            size: st.st_size as u64,
            mtime: st.st_mtime.clamp(0, u32::MAX as i64) as u32,
            child: NONE,
        });
        l.names.extend_from_slice(&name);
    }
    unsafe { libc::closedir(dir) };
}
