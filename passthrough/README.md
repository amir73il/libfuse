# libfuse_passthrough

`libfuse_passthrough` is a C++ library built on top of libfuse that implements
a high-performance passthrough filesystem. It mirrors a specified **source**
directory at a **mountpoint**, delegating all filesystem operations directly to
the source with minimal overhead.

The primary use case is **passthrough-mostly** filesystems: filesystems where
the vast majority of operations pass straight through to the source, but a
module intercepts a small subset to add custom behaviour — such as caching,
tiering, auditing, or HSM stub manifestation — without reimplementing the full
filesystem from scratch.

The library is designed for this: callers register **modules** that intercept
only the operations they care about and chain to the next module or the default
library implementation for everything else.

## Architecture

The library handles all FUSE plumbing internally. Each filesystem operation is
dispatched through the registered module chain before falling back to the
default passthrough implementation, which performs the equivalent `*at(2)`
syscall on the source directory.

A module is a `fuse_passthrough_module` subclass that populates a
`fuse_passthrough_operations` struct with hook functions. Only the operations
a module cares about need to be implemented; all others fall through to the
next module or the default implementation automatically. Each hook receives a
`fuse_path_at` object that bundles the path, inode reference, and FUSE request,
and calls `call_module_next_op(module, op)` to continue the chain.

Modules can store an opaque `uint64_t` state value per inode or per open file
using `get_module_inode_state()` / `set_module_inode_state()` and the
equivalent file-state helpers. This is sufficient to store a pointer to a
heap-allocated object; the module is responsible for freeing it in its
`forget()` and `release()` hooks.

## Kernel Passthrough

When the kernel supports it, the library enables **kernel read/write
passthrough**: the kernel performs I/O directly against the source fd without
involving the FUSE daemon at all. **Kernel readdir passthrough** is also
supported for directory reads (experimental, requires an out-of-tree kernel
patch).

By default, read/write I/O bypasses the module chain entirely and is handled
by the library (or the kernel). A module that needs to intercept I/O must
implement `read_buf()` / `write_buf()` and opt individual files into those
hooks at `open()` time by clearing `fi->passthrough_read` /
`fi->passthrough_write`. This also opts the file out of kernel passthrough for
that operation. Files where the flags remain set bypass the FUSE daemon for I/O
altogether.

## File Handles

Instead of holding a long-lived `O_PATH` fd per inode, the library can store a
persistent file handle and reopen the inode on demand via
`open_by_handle_at(2)`. This requires a backing filesystem that supports
`name_to_handle_at(2)` (e.g. XFS).

File handle based inode tracking enables reliable **NFS export** of the
passthrough mountpoint: the NFS server can encode and later resolve inodes by
handle without requiring the passthrough daemon to keep open file descriptors
for every cached inode.

When the kernel supports `AT_HANDLE_CONNECTABLE`, the library stores parent
information alongside the file handle. This allows inodes that have been
renamed or whose dentries have been evicted to be reconnected to their current
path in the directory tree.

## Modules

### Example module: `trace`

`modules/trace.cpp` is a minimal reference module. It implements every
operation by calling `trace_fd_path_at()` to print path information to stderr,
then forwarding to the next operation in the chain. It demonstrates the full
module pattern without adding any functional behaviour.

## Example filesystem: `passthrough_fs`

`example/passthrough_fs.cc` is a minimal filesystem built on top of
`libfuse_passthrough`. It implements **no filesystem operations of its own** —
it simply initialises the library, optionally registers the `trace` module when
`--debug` is passed, and calls `fuse_passthrough_main()`. It serves both as a
functional passthrough filesystem and as a starting template for building
custom filesystems on top of the library.
