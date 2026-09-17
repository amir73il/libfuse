---
marp: true
theme: default
paginate: true
header: 'FUSE mostly-passthrough filesystems'
footer: 'LPC 2026 BoF · Amir Goldstein · CTERA Networks'
style: |
  section {
    font-size: 28px;
  }
  section.lead h1 {
    font-size: 2.2em;
  }
  section.small {
    font-size: 24px;
  }
  code {
    font-size: 0.85em;
  }
  table {
    font-size: 0.8em;
  }
---

<!-- _class: lead -->

# FUSE mostly-passthrough filesystems

**Amir Goldstein** · CTERA Networks

Linux Plumbers Conference 2026 · BoF · 7 Oct 2026

https://lpc.events/event/20/contributions/2367/

---

# Agenda (45 min)

| Segment | Time |
|---------|------|
| Problem + use cases | ~5 min |
| libfuse_passthrough architecture | ~12 min |
| Live demo | ~5 min |
| fusex / kernel direction | ~8 min |
| **Discussion** | **~15 min** |

**Goal:** when to use the library, how modules work, what kernel changes we need.

---

# The pattern

Many production FUSE filesystems need to:

- Mirror an existing directory tree with **full fidelity**
- Intercept **only a small subset** of operations

**Examples:** cache / tiering gateways · HSM stub manifestation · auditing · cloud gateways with local backing

**They do *not* want to reimplement:** lookup, rename, xattr, readdir, mmap, locking, …

---

# What builders need

- **Small** custom FS code — implement only the ops you intercept
- **Simple** custom FS code — hooks on a module chain, not a monolithic FUSE server
- **NFS export** — persistent file handles, not an open fd per inode
- **Daemon restart** — clients keep working across passthrough daemon reload

Plus: **fast** common-case I/O via kernel passthrough

---

# What exists today

**libfuse examples:** `passthrough`, `passthrough_ll`, `passthrough_hp`
→ Great references — you still own **all** FUSE plumbing

**Kernel:** [FUSE read/write passthrough](https://github.com/torvalds/linux/blob/master/Documentation/filesystems/fuse/fuse-passthrough.rst)
→ Open files can bypass the daemon for I/O

**Gap:** no library for *passthrough + selective hooks* at production quality

→ **libfuse_passthrough**

---

# libfuse_passthrough in one slide

C++ library on libfuse that:

1. Mirrors `source/` at `mountpoint/`
2. Dispatches ops through a **module chain**
3. Falls back to default `*at(2)` passthrough
4. Enables **kernel read/write passthrough** when supported
5. Tracks inodes via **persistent file handles** (`open_by_handle_at`)

```
App → FUSE mount → libfuse_passthrough → [your module] → default → source
                      ↓ kernel passthrough
                   backing file I/O (no daemon)
```

---

# Module chain architecture

High-level libfuse has an optional module stack. Low-level FUSE has no equivalent. `libfuse_passthrough` provides a low-level module chain.

- Register a `fuse_passthrough_module`
- Fill `fuse_passthrough_operations` — **only the hooks you need**
- Each hook receives `fuse_path_at`
- Forward with `call_module_next_op(module, op)`
- Per-inode / per-file state: `get_module_inode_state()` / `set_module_file_state()`

**Example:** `example/passthrough_fs.cc` + optional `trace` module (`--debug`)

---

<!-- _class: small -->

# Module pattern (trace example)

```cpp
static int xmp_getattr(const fuse_path_at &at, struct stat *attr,
                       fuse_file_info *fi) {
    trace_fd_path_at(at);                    // your logic
    return next_op(getattr)(at, attr, fi);   // chain continues
}
```

**HSM sketch (whiteboard):**

- `lookup()` → manifest stub before `next_op(lookup)`
- `open()` → clear `passthrough_read` if serving from cache
- everything else → automatic passthrough

---

# Three paths (with `trace` module)

```
                    FUSE request
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
     getattr          readdir           read
     open, mkdir      (no module)    (kernel PT)
     … (trace hooks)
         │               │               │
         ▼               │               │
    ┌─────────┐          │               │
    │  trace  │          │               │
    └────┬────┘          │               │
         ▼               ▼               │
    ┌─────────────────────────┐          │
    │  default passthrough   │          │
    │  (*at / getdents)       │          │
    └────────────┬────────────┘          │
                 │                       │
                 ▼                       ▼
              source fs            source fs
                                   (no daemon)
```

**trace** implements metadata / open / mkdir / … — not `read` / `readdir`.  
Those stay on the library (or kernel) fast path by default.

---

<!-- _class: small -->

# `fuse_path_at`: syscall-shaped context

| Need | `fuse_path_at` provides |
|------|-------------------------|
| `*at()` dirfd | `dirfd()` — inode fd or `AT_FDCWD` |
| Relative name | `path()` — or empty (`AT_EMPTY_PATH`) |
| Symlink follow | `flags()` — correct `AT_SYMLINK_*` |
| Edge cases | magic symlink via `/proc/self/fd/N` |

Modules write **syscall-shaped** code, not mount-relative path walking.

---

# I/O: default is the fast path

**By default:** read / write / readdir handled by library (or kernel) — **module chain skipped**

**To intercept I/O**, a module must:

1. Implement `read_buf()` / `write_buf()` (or `readdir()`)
2. At `open()` / `opendir()`, clear `fi->passthrough_read` / `fi->passthrough_write`

Caching / tiering modules **opt in** per file; everything else stays on the fast path.

---

# Kernel read/write passthrough (today)

**OPEN-time model:**

1. Daemon opens backing fd → `fuse_passthrough_open()`
2. Kernel assigns `backing_id`
3. `FUSE_OPEN` reply: `FOPEN_PASSTHROUGH` + `backing_id`
4. `read()` / `write()` → kernel → backing file (**no RPC**)

**Requires:** `FUSE_CAP_PASSTHROUGH`, `CAP_SYS_ADMIN` for registration

---

# Persistent file handles

Kernel export handles for `open_by_handle_at(2)` — not `fuse_file_info->fh`.

Track inodes without an open fd per inode.

Enables NFS export and daemon restart without breaking client handles.

**Today (upstream FUSE_LOOKUP by nodeid):** library supports only special-case ext4/XFS handles encoded in userspace.

Falls back to open fds when persistent handles are not available.

**fusex:** general export handles need a protocol extension — kernel decodes handles delivered at identity time (`LOOKUPX` / `READDIRPLUSX`).

---

# Experimental: readdir passthrough

- Opt-in: `readdir_passthrough` (out-of-tree kernel patch today)
- Same `backing_id` model as read/write passthrough
- Conflicts with readdir cache / readdirplus when enabled globally

**Application control (proposed):** `posix_fadvise()` on the directory fd

- `POSIX_FADV_READDIR_NORMAL` — prefer kernel readdir passthrough
- `POSIX_FADV_READDIR_PLUS` — prefer readdirplus (daemon / attrs path)

Lets workloads choose per `opendir`, not only at mount time.

**Discussion:** upstream this path, or wait for READDIRPLUSX + identity-time fh?

---

# Demo

```bash
mkdir -p /tmp/src/A && echo hello > /tmp/src/A/foo

build.deb/example/passthrough_fs --debug --foreground /tmp/src /tmp/mnt

# other terminal:
cat /tmp/mnt/A/foo     # kernel passthrough — quiet daemon
ls -la /tmp/mnt/A      # trace on stderr with --debug
```

**Compare:** `--nopassthrough` → daemon involved in every read/write

---

# Limitations today

| Area | Current state |
|------|---------------|
| Passthrough setup | OPEN-time `backing_id` |
| Server-resolved backing | no kernel decode — full wire I/O |
| Readdir PT | experimental / OOT patch |
| Admin capability | per-file `BACKING_OPEN` |
| fusex / no-open | design in progress |

---

# Where we're headed (fusex)

**Identity-time passthrough** at LOOKUPX / READDIRPLUSX / MKOBJX:

- `BACKING_FSOPEN` once per connection (single backing superblock)
- `name_to_handle_at()` in identity replies
- kernel: `exportfs_decode_fh` → no per-file daemon fds for data path
- fits **no-open** fusex model

See `fusex-passthrough-design.md` in this tree.

---

# fusex passthrough modes

| Mode | Handle | Kernel data path |
|------|--------|------------------|
| **A** `PASSTHROUGH_FH` | export fid on FSOPEN sb | yes |
| **B** `OPAQUE_FH` | server-defined cookie | no (wire I/O) |
| **C** no handle | — | no (wire I/O) |
| **D** legacy | `backing_id` at OPEN | yes (classic FUSE) |

One wire format for kernel-decodable and server-resolved backends.

---

# Questions for the room

1. Passthrough at **identity** (LOOKUPX) vs **OPEN** time?
2. `BACKING_FSOPEN` (once per sb) vs per-file `BACKING_OPEN`?
3. READDIRPLUSX with per-entry passthrough fh — kernel or daemon bulk setup?
4. Opt out of kernel PT for *some* opens on the same inode?
5. What does Mode B (`OPAQUE_FH`) need that Mode A (`PASSTHROUGH_FH`) doesn't?
6. Security: creds at FSOPEN, stale handles / ESTALE?

---

<!-- _class: lead -->

# Get involved

- **Library:** [passthrough/README.md](https://github.com/amir73il/libfuse/blob/libfuse_passthrough/passthrough/README.md)
- **Example:** `example/passthrough_fs.cc` · `modules/trace.cpp`
- **Design:** `fusex-passthrough-design.md`
- **Kernel doc:** `Documentation/filesystems/fuse/fuse-passthrough.rst`

**What are you building? Let's discuss.**

---

<!-- _class: small -->

# Backup: passthrough_hp vs libfuse_passthrough

| | passthrough_hp | libfuse_passthrough |
|--|----------------|---------------------|
| Target | template / max perf | mostly-passthrough + hooks |
| Extension | edit monolith | module chain |
| Kernel PT | manual | built-in |
| Persistent file handles | no | yes (ext4/XFS; fusex for general) |
| Lines to add a feature | hundreds | tens (one module hook) |

---

<!-- _class: small -->

# Backup: security / resources

| Concern | export fh (fusex A) | opaque fh (B) | legacy backing_id |
|---------|---------------------|---------------|-------------------|
| Daemon fds for data | one at FSOPEN | none | per file |
| `CAP_SYS_ADMIN` | once at FSOPEN | N/A | per BACKING_OPEN |
| Remote backend | local sb only | yes | no |
| Stale handle | ESTALE on decode | server error | fd may linger |

---

<!-- _class: small -->

# Presenting this deck

```bash
# Marp CLI (install once)
npm install -g @marp-team/marp-cli

# PDF / PPTX / HTML
marp lpc-2026-passthrough-slides.md -o lpc-2026-passthrough-slides.pdf
marp lpc-2026-passthrough-slides.md -o lpc-2026-passthrough-slides.html

# Or: Marp for VS Code extension → preview + export in Cursor
```
