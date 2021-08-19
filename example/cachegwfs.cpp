/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2017       Nikolaus Rath <Nikolaus@rath.org>
  Copyright (C) 2018       Valve, Inc
  Copyright (C) 2020       CTERA Networks

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This is a "high-performance" version of passthrough_ll.c. While
 * passthrough_ll.c is designed to be as simple as possible, this
 * example intended to be as efficient and correct as possible.
 *
 * cachegwfs mirrors a specified "source" directory under a
 * specified the mountpoint with as much fidelity and performance as
 * possible.
 *
 * If --nocache is specified, the source directory may be changed
 * directly even while mounted and the filesystem will continue
 * to work correctly.
 *
 * Without --nocache, the source directory is assumed to be modified
 * only through the passthrough filesystem. This enables much better
 * performance, but if changes are made directly to the source, they
 * may not be immediately visible under the mountpoint and further
 * access to the mountpoint may result in incorrect behavior,
 * including data-loss.
 *
 * On its own, this filesystem fulfills no practical purpose. It is
 * intended as a template upon which additional functionality can be
 * built.
 *
 * Unless --nocache is specified, is only possible to write to files
 * for which the mounting user has read permissions. This is because
 * the writeback cache requires the kernel to be able to issue read
 * requests for all files (which the passthrough filesystem cannot
 * satisfy if it can't read the file in the underlying filesystem).
 *
 * ## Source code ##
 */

#define FUSE_USE_VERSION 35

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// C includes
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse_lowlevel.h>
#include <fuse_helpers.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/fsuid.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <xfs/xfs.h>

// C++ includes
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <list>
#include "cxxopts.hpp"
#include <mutex>
#include <fstream>
#include <thread>
#include <iomanip>
#include <atomic>
#include <set>

using namespace std;

/* We are re-using pointers to our `struct sfs_inode` and `struct
   sfs_dirp` elements as inodes and file handles. This means that we
   must be able to store pointer a pointer in both a fuse_ino_t
   variable and a uint64_t variable (used for file handles). */
static_assert(sizeof(fuse_ino_t) >= sizeof(void*),
		"void* must fit into fuse_ino_t");
static_assert(sizeof(fuse_ino_t) >= sizeof(uint64_t),
		"fuse_ino_t must be at least 64 bits");

#define XFS_FILEID_TYPE_64FLAG  0x80    /* NFS fileid has 64bit inodes */
#define XFS_FILEID_INO64_GEN (1 | XFS_FILEID_TYPE_64FLAG)
#define XFS_FILEID_INO64_GEN_PARENT (2 | XFS_FILEID_TYPE_64FLAG)
#define FS_FILEID_INO32_GEN 1
#define FS_FILEID_INO32_GEN_PARENT 2

struct fid64 {
	uint64_t ino;
	uint32_t gen;
	uint64_t parent_ino;
	uint32_t parent_gen;
} __attribute__((packed));

struct fid32 {
	uint32_t ino;
	uint32_t gen;
	uint32_t parent_ino;
	uint32_t parent_gen;
} __attribute__((packed));

struct fh_encoder {
	virtual int ino_size() const = 0;
	virtual ino_t ino(struct file_handle &fh) const = 0;
	virtual uint32_t gen(struct file_handle &fh) const = 0;
	virtual ino_t parent_ino(struct file_handle &fh) const = 0;
	virtual uint32_t parent_gen(struct file_handle &fh) const = 0;
	virtual ino_t nodeid(struct file_handle &fh) const = 0;
	virtual void encode(struct file_handle &fh, ino_t ino, uint32_t gen) const = 0;
	virtual ~fh_encoder() {}
};

static struct fid32_encoder : fh_encoder {
	int ino_size() const override {
		return sizeof(uint32_t);
	}
	ino_t ino(struct file_handle &fh) const override {
		return ((struct fid32 *)fh.f_handle)->ino;
	}
	uint32_t gen(struct file_handle &fh) const override {
		return ((struct fid32 *)fh.f_handle)->gen;
	}
	ino_t parent_ino(struct file_handle &fh) const override {
		return ((struct fid32 *)fh.f_handle)->parent_ino;
	}
	uint32_t parent_gen(struct file_handle &fh) const override {
		return ((struct fid32 *)fh.f_handle)->parent_gen;
	}
	ino_t nodeid(struct file_handle &fh) const override {
		// With 32bit ino, FUSE nodeid is encoded from
		// 32bit src_ino and 32bit generation
		return ((uint64_t)gen(fh)) << 32 | ino(fh);
	}
	void encode(struct file_handle &fh, ino_t ino, uint32_t gen) const override {
		// Construct xfs file handle from ino/gen for -o inode32
		fh.handle_bytes = offsetof(struct fid32, parent_ino);
		fh.handle_type = FS_FILEID_INO32_GEN;
		((struct fid32 *)fh.f_handle)->ino = ino;
		((struct fid32 *)fh.f_handle)->gen = gen;
	}
} fid32_encoder;

static struct fid64_encoder : fh_encoder {
	int ino_size() const override {
		return sizeof(uint64_t);
	}
	ino_t ino(struct file_handle &fh) const override {
		return ((struct fid64 *)fh.f_handle)->ino;
	}
	uint32_t gen(struct file_handle &fh) const override {
		return ((struct fid64 *)fh.f_handle)->gen;
	}
	ino_t parent_ino(struct file_handle &fh) const override {
		return ((struct fid64 *)fh.f_handle)->parent_ino;
	}
	uint32_t parent_gen(struct file_handle &fh) const override {
		return ((struct fid64 *)fh.f_handle)->parent_gen;
	}
	ino_t nodeid(struct file_handle &fh) const override {
		return ino(fh);
	}
	void encode(struct file_handle &fh, ino_t ino, uint32_t gen) const override {
		// Construct xfs file handle from ino/gen for -o inode64
		fh.handle_bytes = offsetof(struct fid64, parent_ino);
		fh.handle_type = XFS_FILEID_INO64_GEN;
		((struct fid64 *)fh.f_handle)->ino = ino;
		((struct fid64 *)fh.f_handle)->gen = gen;
	}
} fid64_encoder;

struct xfs_fh {
	struct file_handle fh;
	union {
		struct fid64 fid64;
		struct fid32 fid32;
	} fid;

	xfs_fh() {
		// Initialize file handle buffer to detect -o inode64/inode32
		fh.handle_bytes = sizeof(fid);
		fh.handle_type = 0;
		memset((char *)&fid, 0, sizeof(fid));
	}

	// Return an fh encoder to use for the file_handle read from fs
	// FILEID_INO32_GEN could be xfs with -o inode32, ext4 or many other fs
	// XFS_FILEID_INO64_GEN is xfs specific
	const fh_encoder *get_encoder() const {
		switch (fh.handle_type) {
			case FS_FILEID_INO32_GEN:
			case FS_FILEID_INO32_GEN_PARENT:
				return &fid32_encoder;
			case XFS_FILEID_INO64_GEN:
			case XFS_FILEID_INO64_GEN_PARENT:
				return &fid64_encoder;
		}
		return NULL;
	}

	// Either these values are decoded from fh by fs.decode()
	// or fh buffer is encoded from these values by fs.encode()
	ino_t nodeid{0};
	ino_t ino{0};
	uint32_t gen{0};
};

struct fd_guard {
	int _fd {-1};

	fd_guard() = delete;
	fd_guard(const fd_guard&) = delete;
	fd_guard(fd_guard&&) = delete;
	fd_guard& operator=(fd_guard&&) = delete;
	fd_guard& operator=(const fd_guard&) = delete;

	fd_guard(int fd): _fd(fd) {}
	~fd_guard() {
		if (_fd > 0)
			close(_fd);
	}
};

enum {
	ftype_unknown,
	ftype_root,
	ftype_dir,
	ftype_regular,
	ftype_symlink,
	ftype_special,
};

struct Inode {
	int _fd {0}; // > 0 for long lived O_PATH fd; -1 for open_by_handle
	int _ftype {ftype_unknown};
	xfs_fh src_fh {};
	uint64_t nlookup {0};
	uint64_t folder_id {0};
	std::mutex m;

	bool dead() { return !src_fh.ino; }
	ino_t ino() { return src_fh.ino; }
	uint32_t gen() { return src_fh.gen; }
	ino_t nodeid() { return src_fh.nodeid; }

	// Delete copy constructor and assignments. We could implement
	// move if we need it.
	Inode() = default;
	Inode(const Inode&) = delete;
	Inode(Inode&& inode) = delete;
	Inode& operator=(Inode&& inode) = delete;
	Inode& operator=(const Inode&) = delete;

	void keepfd(fd_guard& newfd);
	void closefd();

	void set_ftype(mode_t mode) {
		if (S_ISDIR(mode))
			_ftype = ftype_dir;
		else if (S_ISREG(mode))
			_ftype = ftype_regular;
		else if (S_ISLNK(mode))
			_ftype = ftype_symlink;
		else
			_ftype = ftype_special;
	}
	bool is_symlink() const { return _ftype == ftype_symlink; }
	bool is_root() const { return _ftype == ftype_root; }
	bool is_dir() const { return is_root() || _ftype == ftype_dir; }

	~Inode() {
		closefd();
	}
};

// Maps files in the source directory tree to inodes
typedef shared_ptr<Inode> InodePtr;
typedef std::map<ino_t, InodePtr> InodeMap;

enum op {
	OP_FD_PATH, // No redirect
	OP_REDIRECT, // Force redirect
	OP_OPEN_RO,
	OP_OPEN_RW,
	OP_OPENDIR,
	OP_LOOKUP,
	OP_STATFS,
	OP_CHMOD,
	OP_CHOWN,
	OP_TRUNCATE,
	OP_UTIMENS,
	OP_LINK,
	OP_RENAME,
	OP_UNLINK,
	OP_SYMLINK,
	OP_MKDIR,
	OP_RMDIR,
	OP_MKNOD,
	OP_GETXATTR,
	OP_SETXATTR,
	OP_COPY,
	OP_ALL,
};

const std::map<enum op, const char *> op_names = {
	{ OP_OPEN_RO, "open_ro" },
	{ OP_OPEN_RW, "open_rw" },
	{ OP_OPENDIR, "opendir" },
	{ OP_LOOKUP, "lookup" },
	{ OP_SYMLINK, "symlink" },
	{ OP_STATFS, "statfs" },
	{ OP_CHMOD, "chmod" },
	{ OP_CHOWN, "chown" },
	{ OP_TRUNCATE, "truncate" },
	{ OP_UTIMENS, "utimens" },
	{ OP_MKDIR, "mkdir" },
	{ OP_RMDIR, "rmdir" },
	{ OP_MKNOD, "mknod" },
	{ OP_LINK, "link" },
	{ OP_RENAME, "rename" },
	{ OP_UNLINK, "unlink" },
	{ OP_GETXATTR, "getxattr" },
	{ OP_SETXATTR, "setxattr" },
	{ OP_COPY, "copy" },
	{ OP_ALL, "all" },
};
static const char *op_name(enum op op) {
	auto iter = op_names.find(op);
	if (iter == op_names.end())
		return "";
	return iter->second;
}

// Redirect config that can be changed in runtime
struct Redirect {
	std::string read_xattr;
	std::string write_xattr;
	std::string readdir_xattr;
	vector<string> xattr_prefixes;
	std::unordered_set<enum op> ops; // fs operations to redirect
	std::unordered_set<uint64_t> folder_ids; // folder ids to redirect

	bool test_op(enum op op) {
		return ops.count(op) > 0;
	}
	void set_op(enum op op) {
		ops.insert(op);
	}
	bool test_folder_id(uint64_t folder_id) {
		return folder_ids.count(folder_id) > 0;
	}
	void set_folder_id(uint64_t folder_id) {
		folder_ids.insert(folder_id);
	}

	void set_op(const string &name) {
		auto it = find_if(op_names.begin(), op_names.end(),
				[name](decltype(*op_names.begin()) &p) {
					return p.second == name;
				});
		if (it != op_names.end())
			set_op(it->first);
		else
			cerr << "WARNING: unknown redirect operation " << name << endl;
	}
	void set_folder_id(const string &name) {
		uint64_t folder_id = strtoull(name.c_str(), NULL, 10);
		if (folder_id)
			folder_ids.insert(folder_id);
		else
			cerr << "WARNING: illegal redirect folder id " << name << endl;
	}
};

#define CONFIG_FILE "/etc/cachegwfs.conf"

static Redirect *read_config_file();

struct Fs {
	// Must be acquired *after* any Inode.m locks.
	std::mutex mutex;
	InodeMap inodes; // protected by mutex
	InodePtr root;
	uid_t uid;
	gid_t gid;
	double timeout;
	bool debug;
	std::string source;
	std::string redirect_path;
	std::string config_file{CONFIG_FILE};
	size_t blocksize;
	dev_t src_dev;
	bool nosplice;
	bool nocache;
	bool wbcache;
	bool rwpassthrough;
	bool ino32 {false};
	bool bulkstat {true};
	int at_connectable {0};
	atomic_ulong num_keepfd{0};
	unsigned long max_keepfd{0};

	Fs() {
		// Initialize a dead inode
		inodes[0].reset(new Inode());
		// Get own credentials
		uid = geteuid();
		gid = getegid();
		// Initialize default redirect, but do not mark it valid
		_redirect.reset(new Redirect());
	}

	// Lazy reload config file on next redirect test
	void reset_config() {
		config_is_valid.clear();
	}
	shared_ptr<Redirect> redirect() {
		auto reload = !config_is_valid.test_and_set();
		if (reload) {
			auto r = shared_ptr<Redirect>(read_config_file());
			if (r != nullptr) {
				atomic_store(&_redirect, r);
				return r;
			}
		}
		return atomic_load(&_redirect);
	}
	bool redirect_op(enum op op) {
		auto r = redirect();
		return op == OP_REDIRECT || r->test_op(OP_ALL) || r->test_op(op);
	}

	const fh_encoder *get_encoder() const { return encoder; }
	bool decode(xfs_fh &xfh);
	bool encode(xfs_fh &xfh);

	void init_root();
	int open_by_fh(InodePtr inode);
	uint32_t xfs_bulkstat_gen(__u64 ino);

private:
	bool get_root_fh(ino_t src_ino, bool connectable = true);

	atomic_flag config_is_valid {ATOMIC_FLAG_INIT};
	shared_ptr<Redirect> _redirect;
	int _bulkstat_fd{-1};
	const fh_encoder *encoder{NULL};
};
static Fs fs{};

#define NULL_UID static_cast<uid_t>(-1)
#define NULL_GID static_cast<gid_t>(-1)

struct Cred {
	uid_t _uid {NULL_UID};
	gid_t _gid {NULL_GID};

	Cred() = delete;
	Cred(const Cred&) = delete;
	Cred(Cred&&) = delete;
	Cred& operator=(Cred&&) = delete;
	Cred& operator=(const Cred&) = delete;

	Cred(uid_t uid, gid_t gid) {
		// Set requestor credentials
		if (uid != fs.uid)
			_uid = setfsuid(uid);
		if (gid != fs.gid)
			_gid = setfsgid(gid);
	}
	~Cred() {
		auto savederrno = errno;

		if (_uid != NULL_UID)
			setfsuid(_uid);
		if (_gid != NULL_GID)
			setfsgid(_gid);

		errno = savederrno;
	}
};


#define FUSE_BUF_COPY_FLAGS			\
	(fs.nosplice ?				\
	 FUSE_BUF_NO_SPLICE :			\
	 static_cast<fuse_buf_copy_flags>(0))


// Called under inode.m lock
void Inode::keepfd(fd_guard& newfd)
{
	// Check is not under fs lock. It's ok to pass max_keepfd a bit
	if (fs.num_keepfd.load(memory_order_relaxed) >= fs.max_keepfd)
		return;

	// Upgrade short lived fd to long lived fd in inode cache
	_fd = newfd._fd;
	newfd._fd = -1;
	fs.num_keepfd++;
}

void Inode::closefd()
{
	if (_fd > 0) {
		close(_fd);
		fs.num_keepfd--;
	}
}

// Check if this is an empty place holder (a.k.a stub file).
// See: https://github.com/github/libprojfs/blob/master/docs/design.md#extended-attributes
static bool should_redirect_fd(int fd, const char *procname, enum op op,
				uint64_t folder_id)
{
	if (op == OP_FD_PATH)
		return false;

	if (fs.redirect_op(OP_ALL))
		return true;

	if (!fs.redirect_op(op))
		return false;

	bool rw = false, is_dir = false;
	if (op == OP_OPENDIR || op == OP_LOOKUP)
		is_dir = true;
	else if (op == OP_OPEN_RO)
		rw = false;
	else if (op == OP_OPEN_RW)
		rw = true;
	else
		return true;

	auto r = fs.redirect();
	if (rw && folder_id && r->test_folder_id(folder_id))
		return true;

	const string &redirect_xattr = rw ? r->write_xattr :
		(is_dir ? r->readdir_xattr : r->read_xattr);
	if (redirect_xattr.empty())
		return true;

	ssize_t res;
	if (procname)
		res = getxattr(procname, redirect_xattr.c_str(), NULL, 0);
	else
		res = fgetxattr(fd, redirect_xattr.c_str(), NULL, 0);
	return res > 0;
}

// Convert <dirfd+name> for system calls that take an O_PATH fd.
// Returns dirfd and sets outpath to redirected path relative to dirfd.
// There is no elevated refcount on returned dirfd.
//
// If @op is in redirect ops, then @outpath is set to redirected path
// and AT_FDCWD is returned.
//
// @name may be empty, in which case non redirected @outpath is set to
// /proc/self/fd/<dirfd> and the special value AT_PROCFD is returned.
// This value cannot be used for *at() syscalls!!!
#define AT_PROCFD (AT_FDCWD - 1)
#define IS_REDIRECETED(dirfd) ((dirfd) == AT_FDCWD)

static int get_fd_path_at(int dirfd, const char *name, enum op op, string &outpath,
	uint64_t folder_id = 0)
{
	char procname[64];
	sprintf(procname, "/proc/self/fd/%i", dirfd);
	char linkname[PATH_MAX];
	int n = 0;
	bool redirect = should_redirect_fd(dirfd, procname, op, folder_id);

	if (fs.debug || redirect) {
		n = readlink(procname, linkname, PATH_MAX);
	}
	if (n > 0 && fs.debug) {
		linkname[n] = 0;
		cerr << "DEBUG: " << op_name(op) << "(" << name << ")"
			<< " @ " << procname << " -> " << linkname << endl;
	}
	int prefix = fs.source.size();
	if (redirect && prefix && n >= prefix &&
	    !memcmp(fs.source.c_str(), linkname, prefix)) {
		if (fs.debug)
			cerr << "DEBUG: redirect " << op_name(op) << "(" << name << ")"
				<< " @ " << dirfd << " |=> ." << linkname + prefix << endl;
		outpath = fs.redirect_path;
		if (fs.redirect_path.empty())
			outpath.append(linkname);
		else
			outpath.append(linkname + prefix, n - prefix);
		if (*name) {
			outpath.append("/");
			outpath.append(name);
		}
		return AT_FDCWD;
	} else if (redirect && prefix) {
		// We need to redirect, but we don't know where to
		// Return an invalid path so operation will fail
		cerr << "ERROR: redirect " << op_name(op) << "(" << name << "): "
			<< linkname << " not under " << fs.source << endl;
		outpath = "";
		return AT_FDCWD;
	} else if (!*name) {
		// No redirect - convert dirfd+"" to safe /proc/ path
		outpath = procname;
		return AT_PROCFD;
	} else {
		// No redirect - return the dirfd+name we got
		outpath = name;
		return dirfd;
	}
}

// TODO: factor this out as helper to get_fd_path_at()
static void print_fd_path(int fd)
{
	string path;
	(void)get_fd_path_at(fd, "", OP_FD_PATH, path);
}

static int open_redirect_fd(int dirfd, const char *name, int flags)
{
	string path;
	get_fd_path_at(dirfd, name, OP_REDIRECT, path);
	return open(path.c_str(), flags & ~O_NOFOLLOW);
}

static enum op redirect_open_op(int flags)
{
	return (flags & O_ACCMODE) == O_RDONLY ? OP_OPEN_RO : OP_OPEN_RW;
}

static int check_safe_fd(int fd, enum op op, uint64_t folder_id)
{
	// cachegw manager takes an exclusive lock before making file a stub
	if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
		auto saverr = errno;
		cerr << "INFO: file is locked for read/write access." << endl;
		errno = saverr;
		return -1;
	}

	// Check that file is still not a stub after lock
	if (!should_redirect_fd(fd, NULL, op, folder_id))
		return 0;

	cerr << "INFO: file open raced with evict." << endl;
	errno = EAGAIN;
	return -1;
}

// Extract source <ino;gen> and FUSE ino from source file handle
bool Fs::decode(xfs_fh &xfh)
{
	if (!encoder || encoder != get_encoder())
		return false;

	xfh.nodeid = encoder->nodeid(xfh.fh);
	xfh.ino = encoder->ino(xfh.fh);
	xfh.gen = encoder->gen(xfh.fh);
	return true;
}

// Construct file handle buffer from <ino;gen> for LOOKUP(".")
bool Fs::encode(xfs_fh &xfh)
{
	if (!encoder)
		return false;

	encoder->encode(xfh.fh, xfh.ino, xfh.gen);
	return true;
}


uint32_t Fs::xfs_bulkstat_gen(__u64 ino)
{
	__s32 count = 0;
	struct xfs_bstat bstat = { };
	struct xfs_fsop_bulkreq breq = {
		.lastip = &ino,
		.icount = 1,
		.ubuffer = (void *)&bstat,
		.ocount = &count,
	};

	if (_bulkstat_fd < 0)
		_bulkstat_fd = open(source.c_str(), O_DIRECTORY | O_RDONLY);
	if (_bulkstat_fd < 0 ||
	    ioctl(_bulkstat_fd, XFS_IOC_FSBULKSTAT_SINGLE, &breq) != 0) {
		auto saverr = errno;
		cerr << "INFO: failed to bulkstat inode " << ino << ", errno=" << errno << endl;
		errno = saverr;
		// Try open by handle with zero generation
		return 0;
	}

	if (debug) {
		cerr << "DEBUG: xfs_bulkstat_gen(): ino=" << ino << ", count=" << count
			<< ", bs_ino=" << bstat.bs_ino  << ", bs_gen=" << bstat.bs_gen <<  endl;
	}

	return bstat.bs_gen;
}

int Fs::open_by_fh(InodePtr inode)
{
	int fd = open_by_handle_at(root->_fd, &inode->src_fh.fh, O_PATH);
	if (fd < 0)
		return fd;

	if (debug)
		print_fd_path(fd);

	return fd;
}

// Flag used to request connectable file handle (requires a kernel patch)
#ifndef AT_CONNECTABLE
#define AT_CONNECTABLE         0x10000 /* Request a connectable file handle */
#endif

bool Fs::get_root_fh(ino_t src_ino, bool connectable)
{
	at_connectable = connectable ? AT_CONNECTABLE : 0;
	// O_PATH mount fd is used as a hint to decode connectable file handles.
	// Without kernel patch, open_by_file_handle() with O_PATH fd will fail.
	root->_fd = open(source.c_str(), O_DIRECTORY |
			(connectable ? O_PATH : O_RDONLY));
	if (root->_fd == -1)
		err(1, "ERROR: open(\"%s\")", source.c_str());

	int mount_id;
	struct xfs_fh xfs_fh{};
	auto ret = name_to_handle_at(root->_fd, "", &xfs_fh.fh, &mount_id,
				     AT_EMPTY_PATH | at_connectable);
	if (ret == -1) {
		if (!connectable)
			err(1, "ERROR: name_to_handle_at(\"%s\")", source.c_str());
		// Maybe connectable fh not supported - retry with non-connectable
		close(root->_fd);
		return get_root_fh(src_ino, false);
	}

	cout << "connectable file handles "
		<< (connectable ? "" : "not " ) << "supported" << endl;

	encoder = xfs_fh.get_encoder();
	if (!encoder)
		errx(1, "ERROR: source filesystem type not supported");
	if (!decode(xfs_fh) || src_ino != xfs_fh.ino)
		errx(1, "ERROR: failed decoding root file handle");

	root->src_fh = xfs_fh;
	root->src_fh.nodeid = FUSE_ROOT_ID;

	// Auto detect xfs with -o inode32 (or ext4)
	ino32 = (encoder->ino_size() == sizeof(uint32_t));
	// bulkstat support is an indication of xfs
	bulkstat = xfs_bulkstat_gen(src_ino);
	if (!bulkstat && errno == EPERM)
		errx(1, "ERROR: insufficient privileges");
	cout << "source filesystem looks like "
		<< ((bulkstat || !ino32) ? "xfs" : "ext4")
		<< " -o inode" << (ino32 ? "32" : "64") << endl;
	return true;
}

void Fs::init_root()
{
	root.reset(new Inode());
	root->nlookup = 9999;

	struct stat stat;
	auto ret = lstat(source.c_str(), &stat);
	if (ret == -1)
		err(1, "ERROR: failed to stat source (\"%s\")", source.c_str());
	if (!S_ISDIR(stat.st_mode))
		errx(1, "ERROR: source is not a directory");
	src_dev = stat.st_dev;
	root->_ftype = ftype_root;
	get_root_fh(stat.st_ino);
}

// Short lived reference of inode to keep fd open
struct InodeRef {
	InodePtr i;
	int fd {-1}; // Short lived O_PATH fd
	ino_t ino() const { return i->ino(); }
	uint32_t gen() const { return i->gen(); }
	ino_t nodeid() const { return i->nodeid(); }
	uint64_t folder_id() const { return i->folder_id; }
	bool is_redirected() const { return (dirfd == AT_FDCWD); }
	bool is_symlink() const { return i->is_symlink(); }
	bool is_root() const { return i->is_root(); }
	bool is_dir() const { return i->is_dir(); }

	// Delete copy constructor and assignments. We could implement
	// move if we need it.
	InodeRef() = delete;
	InodeRef(const InodeRef&) = delete;
	InodeRef(InodeRef&& inode) = delete;
	InodeRef& operator=(InodeRef&& inode) = delete;
	InodeRef& operator=(const InodeRef&) = delete;

	InodeRef(InodePtr inode) : i(inode)
	{
		if (i->dead())
			return;

		fd = i->_fd;
		if (fd == -1) {
			fd = fs.open_by_fh(inode);
		}
		if (fd == -1) {
			fd = -errno;
			cerr << "INFO: failed to open fd for inode " << ino()
				<< ", err=" << fd  << ", gen=" << gen() <<  endl;
		}
	}

	int error(fuse_req_t req) {
		int err = 0;

		if (i->dead())
			err = ENOENT;
		else if (fd < 0)
			err = -fd;

		if (err)
			fuse_reply_err(req, err);

		return err;
	}

	// Convert fd to path for system calls that do not take an O_PATH fd.
	// May return a magic /proc symlink, so syscalls that use the returned
	// path cannot use NOFOLLOW. To avoid unintended following of symlinks
	// on redirected path, do not redirect opertions on symlink inodes.
	const char *get_path(enum op op, bool follow = false) {
		if (!follow && is_symlink())
			op = OP_FD_PATH;
		dirfd = get_fd_path_at(fd, "", op, path);
		return path.c_str();
	}

	~InodeRef() {
		if (fd > 0 && fd != i->_fd)
			close(fd);
	}

private:
	int dirfd{-1};
	string path; // Either /proc magic symlink path or redirected path
};

static InodePtr get_inode(fuse_ino_t ino) {
	if (ino == FUSE_ROOT_ID)
		return fs.root;

	lock_guard<mutex> g_fs {fs.mutex};
	auto iter = fs.inodes.find(ino);

	if (iter == fs.inodes.end()) {
		cerr << "INTERNAL ERROR: Unknown inode " << ino << endl;
		// return a "dead" inode
		return fs.inodes[0];
	}
	return iter->second;
}


// The object that hangs off of fi->fh for an open FUSE file (or directory)
struct FileHandle {
	virtual int get_fd() = 0;
	virtual ~FileHandle() {};
};

struct File : public FileHandle {
	int _fd {-1};

	int get_fd() override { return _fd > 0 ? _fd : _redirect_fd; };

	int get_redirect_fd() { return _redirect_fd; };

	File() = delete;
	File(const File&) = delete;
	File& operator=(const File&) = delete;

	File(int fd, int rfd) : _fd(fd), _redirect_fd(rfd) {
		if (fs.debug)
			cerr << "DEBUG: open(): fd=" << _fd << " rfd=" << _redirect_fd << endl;
	}
	~File() {
		if (fs.debug)
			cerr << "DEBUG: close(): fd=" << _fd << " rfd=" << _redirect_fd << endl;
		if (_fd > 0)
			close(_fd);
		if (_redirect_fd > 0)
			close(_redirect_fd);
	}

private:
	int _redirect_fd {-1};
};

static File *get_file(fuse_file_info *fi)
{
	return reinterpret_cast<File*>(fi->fh);
}

static FileHandle *get_file_handle(fuse_file_info *fi)
{
	return reinterpret_cast<FileHandle*>(fi->fh);
}

static int get_file_fd(fuse_file_info *fi)
{
	return get_file_handle(fi)->get_fd();
}

static void release_file_handle(fuse_file_info *fi)
{
	auto fh = get_file_handle(fi);
	delete fh;
	fi->fh = 0;
}

static void fuse_reply_fd_err(fuse_req_t req, int err)
{
	if (err == ENFILE || err == EMFILE)
		cerr << "ERROR: Reached maximum number of file descriptors." << endl;
	fuse_reply_err(req, err);
}

static File *fd_open(int fd, bool redirected, enum op op, uint64_t folder_id,
		     int dirfd, const char *name, int flags)
{
	auto rfd = -1;

	if (redirected) {
		// fd is already redirected - swap it with rfd
		rfd = fd;
		fd = -1;
	} else if (check_safe_fd(fd, op, folder_id) == -1) {
		return NULL;
	} else if (fs.redirect_op(OP_COPY)) {
		// open redirect fd in addition to the bypass fd.
		// when called from create(), we must not try to create
		// a file in redirect path, only to open it.
		rfd = open_redirect_fd(dirfd, name, flags & ~O_CREAT);
		if (rfd == -1)
			return NULL;
	}

	auto fh = new (nothrow) File(fd, rfd);
	if (!fh)
		errno = ENOMEM;

	return fh;
}

static void sfs_init(void *userdata, fuse_conn_info *conn) {
	(void)userdata;
	if (conn->capable & FUSE_CAP_EXPORT_SUPPORT)
		conn->want |= FUSE_CAP_EXPORT_SUPPORT;

	if (fs.wbcache && conn->capable & FUSE_CAP_WRITEBACK_CACHE)
		conn->want |= FUSE_CAP_WRITEBACK_CACHE;

	if (conn->capable & FUSE_CAP_FLOCK_LOCKS)
		conn->want |= FUSE_CAP_FLOCK_LOCKS;

	if (conn->capable & FUSE_CAP_POSIX_ACL)
		conn->want |= FUSE_CAP_POSIX_ACL;

	// Use splicing if supported. Since we are using writeback caching
	// and readahead, individual requests should have a decent size so
	// that splicing between fd's is well worth it.
	if (conn->capable & FUSE_CAP_SPLICE_WRITE && !fs.nosplice)
		conn->want |= FUSE_CAP_SPLICE_WRITE;
	if (conn->capable & FUSE_CAP_SPLICE_READ && !fs.nosplice)
		conn->want |= FUSE_CAP_SPLICE_READ;
	if (fs.rwpassthrough) {
		if (conn->capable & FUSE_CAP_PASSTHROUGH)
			conn->want |= FUSE_CAP_PASSTHROUGH;
		else
			fs.rwpassthrough = false;
	}
	cout << "kernel read/write passthrough "
		<< (fs.rwpassthrough ? "enabled" : "disabled" ) << endl;
}


static void sfs_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
	(void)fi;
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	struct stat attr;
	auto res = fstatat(inode.fd, "", &attr,
			AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	fuse_reply_attr(req, &attr, fs.timeout);
}


static void do_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		int valid, struct fuse_file_info* fi) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	int res;

	if (valid & FUSE_SET_ATTR_MODE) {
		if (fi) {
			res = fchmod(get_file_fd(fi), attr->st_mode);
		} else {
			res = chmod(inode.get_path(OP_CHMOD, true), attr->st_mode);
		}
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
		uid_t uid = (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : NULL_UID;
		gid_t gid = (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : NULL_GID;

		res = fchownat(AT_FDCWD, inode.get_path(OP_CHOWN), uid, gid, 0);
		if (res == -1)
			goto out_err;
	}
	if (valid & FUSE_SET_ATTR_SIZE) {
		if (fi) {
			res = ftruncate(get_file_fd(fi), attr->st_size);
		} else {
			res = truncate(inode.get_path(OP_TRUNCATE, true), attr->st_size);
		}
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		struct timespec tv[2];

		tv[0].tv_sec = 0;
		tv[1].tv_sec = 0;
		tv[0].tv_nsec = UTIME_OMIT;
		tv[1].tv_nsec = UTIME_OMIT;

		if (valid & FUSE_SET_ATTR_ATIME_NOW)
			tv[0].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_ATIME)
			tv[0] = attr->st_atim;

		if (valid & FUSE_SET_ATTR_MTIME_NOW)
			tv[1].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_MTIME)
			tv[1] = attr->st_mtim;

		if (fi)
			res = futimens(get_file_fd(fi), tv);
		else {
#ifdef HAVE_UTIMENSAT
			res = utimensat(AT_FDCWD, inode.get_path(OP_UTIMENS), tv, 0);
#else
			res = -1;
			errno = EOPNOTSUPP;
#endif
		}
		if (res == -1)
			goto out_err;
	}
	return sfs_getattr(req, ino, fi);

out_err:
	fuse_reply_err(req, errno);
}


static void sfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		int valid, fuse_file_info *fi) {
	(void) ino;
	do_setattr(req, ino, attr, valid, fi);
}


static int do_lookup(InodeRef& parent, const char *name,
		fuse_entry_param *e) {
	if (fs.debug)
		cerr << "DEBUG: lookup(): name=" << name
			<< ", parent_ino=" << parent.ino()
			<< ", parent_folder_id=" << parent.folder_id() << endl;
	memset(e, 0, sizeof(*e));
	e->attr_timeout = fs.timeout;
	e->entry_timeout = fs.timeout;

	int newfd;
	if (strcmp(name, ".") == 0) {
		newfd = fs.open_by_fh(parent.i);
	} else if (strcmp(name, "..") == 0) {
		newfd = openat(parent.fd, name, O_PATH | O_NOFOLLOW);
	} else {
		// Check if reading parent directory should be redirected
		// and lookup child in redirect path before lookup in source path
		// to trigger populate of place holder directory
		string path;
		int dirfd = get_fd_path_at(parent.fd, name, OP_LOOKUP, path);
		if (dirfd != parent.fd &&
		    faccessat(dirfd, path.c_str(), F_OK, AT_SYMLINK_NOFOLLOW)) {
			return errno;
		}
		newfd = openat(parent.fd, name, O_PATH | O_NOFOLLOW);
	}
	if (newfd == -1)
		return errno;

	fd_guard newfd_g(newfd);
	auto res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		auto saveerr = errno;
		if (fs.debug)
			cerr << "DEBUG: lookup(): fstatat failed" << endl;
		return saveerr;
	}

	int mount_id;
	struct xfs_fh xfs_fh{};
	res = name_to_handle_at(newfd, "", &xfs_fh.fh, &mount_id,
				AT_EMPTY_PATH | fs.at_connectable);
	if (res == -1) {
		auto saveerr = errno;
		if (fs.debug)
			cerr << "DEBUG: lookup(): name_to_handle_at failed" << endl;
		return saveerr;
	}

	auto src_ino = e->attr.st_ino;
	auto root_ino = fs.root->ino();

	if (e->attr.st_dev != fs.src_dev) {
		cerr << "WARNING: Mountpoints in the source directory tree will be hidden." << endl;
		return ENOTSUP;
	} else if (src_ino == FUSE_ROOT_ID) {
		cerr << "ERROR: Source directory tree must not include inode "
			<< FUSE_ROOT_ID << endl;
		return EIO;
	} else if (src_ino == root_ino) {
		// found root when reconnecting directory file handle, i.e. lookup(ino, "..")
		e->ino = FUSE_ROOT_ID;
		return 0;
	} else if (!fs.decode(xfs_fh)) {
		cerr << "WARNING: Source directory expected to be XFS or ext4." << endl;
		return ENOTSUP;
	} else if (src_ino != xfs_fh.ino) {
		cerr << "ERROR: Source st_ino " << src_ino <<
			" and file handle ino " << xfs_fh.ino << " mismatch." << endl;
		return EIO;
	}

	e->ino = xfs_fh.nodeid;
	e->generation = xfs_fh.gen;

#ifdef DEBUG_INTERNAL_ERROR_UNKNOWN_INO
	// Fake lookup success without inserting to inodes map.
	// Listing root dir works, but stat on entries returns ENOENT.
	return 0;
#endif

	unique_lock<mutex> fs_lock {fs.mutex};
	auto iter = fs.inodes.find(e->ino);
	bool found = (iter != fs.inodes.end());
	InodePtr inode_ptr;

	if (found) {
		inode_ptr = iter->second;
	} else try {
		fs.inodes[e->ino].reset(new Inode());
		inode_ptr = fs.inodes[e->ino];
	} catch (std::bad_alloc&) {
		return ENOMEM;
	}

	// Folder id of first level subdirs is their name.
	// If subdir name is not a decimal number, the folder id is 0.
	// For all other inodes, it is inheritted from the parent.
	uint64_t folder_id = parent.folder_id();
	auto is_folder_root = parent.is_root() && S_ISDIR(e->attr.st_mode);
	if (is_folder_root) {
		folder_id = strtoull(name, NULL, 10);
		if (fs.debug && !folder_id)
			cerr << "DEBUG: lookup(): first level subdir name '" << name
				<< "' is not a folder id." << endl;
	}
	// For non-dir looked up by name, store parent fh if we can use it to open
	// an fd with a connected path or keep a long lived fd with connected path
	auto is_connectable = parent.is_dir() && !S_ISDIR(e->attr.st_mode);
	auto keepfd = is_folder_root;
	if (is_connectable && !fs.at_connectable) {
		is_connectable = false;
		keepfd = true;
	}

	// Use convenience reference to Inode
	Inode &inode = *inode_ptr;
	if (found) { // found existing inode
		auto dead = inode.dead();
		fs_lock.unlock();
		if (dead) {
			cerr << "WARNING: lookup(): inode " << src_ino
				<< " raced with forget (try again)." << endl;
			return ESTALE;
		}
		if (fs.debug)
			cerr << "DEBUG: lookup(): inode " << src_ino << " (userspace) already known"
				<< "; gen = " << xfs_fh.gen << ",fd = " << inode._fd << endl;
		lock_guard<mutex> g {inode.m};
		if (inode.gen() != xfs_fh.gen) {
			if (fs.debug)
				cerr << "DEBUG: lookup(): inode " << src_ino
					<< " generation " << inode.gen()
					<< " mismatch - reused inode." << endl;
			inode.src_fh = xfs_fh;
		}
		// Update parent on lookup by name, because inode may have been moved
		// or inode may have been reconnected after it was found by LOOKUP "."
		if (is_connectable) {
			if (fs.debug &&
			    parent.ino() != fs.get_encoder()->parent_ino(xfs_fh.fh))
                                cerr << "DEBUG: lookup(): inode " << src_ino
                                        << " parent " << parent.ino()
                                        << " updated." << endl;
			inode.src_fh = xfs_fh;
		}
		// Maybe update long lived fd and folder id if opened initially by handle
		if (!inode.folder_id)
			inode.folder_id = folder_id;
		if (inode._fd == -1 && keepfd)
			inode.keepfd(newfd_g);
		inode.nlookup++;
	} else { // no existing inode
		/* This is just here to make Helgrind happy. It violates the
		   lock ordering requirement (inode.m must be acquired before
		   fs.mutex), but this is of no consequence because at this
		   point no other thread has access to the inode mutex */
		lock_guard<mutex> g {inode.m};
		inode.set_ftype(e->attr.st_mode);
		inode.src_fh = xfs_fh;
		inode.nlookup = 1;
		inode.folder_id = folder_id;
		// Mark inode for open_by_handle
		inode._fd = -1;
		if (keepfd) {
			// Hold long lived fd for subdirs of root
			inode.keepfd(newfd_g);
		}
		fs_lock.unlock();

		if (fs.debug)
			cerr << "DEBUG: lookup(): created userspace inode " << src_ino
				<< "; gen = " << xfs_fh.gen << ",fd = " << inode._fd << endl;
	}

	return 0;
}


static void sfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
	fuse_entry_param e {};
	InodePtr inode_p;
	if (strcmp(name, ".") == 0) {
		auto i = new (nothrow) Inode();
		if (!i) {
			fuse_reply_err(req, ENOMEM);
			return;
		}
		inode_p.reset(i);
		// Request to open disconnected inode by FUSE file handle
		// FUSE LOOKUP(ino, ".") does not pass the generation
		inode_p->_fd = 0;
		auto &fh = inode_p->src_fh;
		fh.nodeid = fh.ino = parent;
		// With 32bit ino, FUSE nodeid is encoded from 32bit src_ino
		// and 32bit generation. With XFS, we try to use bulkstat to
		// get generation from ino
		if (fs.ino32) {
			fh.gen = parent >> 32;
			fh.ino &= 0xffffffff;
		} else if (fs.bulkstat) {
			fh.gen = fs.xfs_bulkstat_gen(parent);
		}
		// Reconstruct file handle from <ino;gen>
		fs.encode(fh);
	} else {
		inode_p = get_inode(parent);
	}

	InodeRef inode_ref(inode_p);
	if (inode_ref.error(req))
		return;

	auto err = do_lookup(inode_ref, name, &e);
	if (err == ENOENT) {
		e.attr_timeout = fs.timeout;
		e.entry_timeout = fs.timeout;
		e.ino = e.attr.st_ino = 0;
		fuse_reply_entry(req, &e);
	} else if (err) {
		fuse_reply_fd_err(req, err);
	} else {
		fuse_reply_entry(req, &e);
	}
}

static tuple<bool, gid_t, gid_t> get_sgid_and_gids(int dirfd, const string &path)
{
	struct stat st;

	// The parent
	if (fstatat(dirfd, "", &st,
				AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) == -1)
	{
		cerr << "ERROR: stat parent of new file: " << strerror(errno) << ". " <<
			"Ignoring SGID if exist and chowning also group" << endl;

		return {false, -1, -1};
	}

	auto parent_sgid = st.st_mode & S_ISGID;
	auto parent_gid = st.st_gid;

	// The new file. This is just to get gid for debug print.
	if (fstatat(dirfd, path.c_str(), &st,
				AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) == -1)
	{
		cerr << "ERROR: stat new file: " << strerror(errno) << endl;

		return {parent_sgid, parent_gid, -1};
	}

	return { parent_sgid, parent_gid, st.st_gid };
}

// Assumes that op returns -1 on failure
static int as_user(fuse_req_t req, int dirfd, const string &path,
		const string &opname, function<int()> op)
{
	auto c = fuse_req_ctx(req);

	if (!c)
	{
		cerr << "WARNING: No fuse context: very strange" << endl;
		return op();
	}

	{
		Cred cred(c->uid, c->gid);
		auto ret = op();

		if (ret == 0 || errno != EACCES)
			return ret;
	}

	/* Might fail due to setfsuid/gid not setting supplementary unix groups:
	 * If the permission for the operation should be granted due to the
	 * folder owner-group being one of the caller's supplementary groups,
	 * it won't be respected: fallback to do it as root with an extra chown
	 */
	if (fs.debug)
	{
		cerr << "DEBUG: " << opname << " " << path <<
			" as user " << c->uid << "," << c->gid <<
			": access denied. " <<
			"fallback to do as root and chown" <<  endl;
	}

	auto opret = op();

	if (opret == -1)
		return opret;

	auto operrno = errno;

	auto gid = c->gid;
	auto [is_sgid, parent_gid, file_gid] = get_sgid_and_gids(dirfd, path);

	if (is_sgid)
	{
		if (parent_gid != file_gid)
		{
			cerr << "ERROR: parent with SGID, parent gid=" <<
			       parent_gid << " but file created with gid=" <<
			       file_gid << ". Will fix using chown. " << endl;

			gid = parent_gid;
		}
		else
		{
			if (fs.debug)
			{
				cerr << "DEBUG: file group already set to " <<
				       	file_gid << " due to SGID. "
					"Chown only file owner" << endl;
			}

			// To leave file group as is
			gid = -1;
		}
	}

	auto chownret = fchownat(dirfd, path.c_str(), c->uid, gid,
			AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);

	if (chownret == -1)
		cerr << "ERROR: chown new file failed: " << strerror(errno) << endl;

	// It's important to return original op ret value, specialy for open
	errno = operrno;
	return opret;
}


static int do_mkdir(fuse_req_t req, int fd, const char *name, mode_t mode) {
	string path;
	int dirfd = get_fd_path_at(fd, name, OP_MKDIR, path);
	return as_user(req, dirfd, path, __func__, [&](){
			return mkdirat(dirfd, path.c_str(), mode);
		});
}

static int do_symlink(fuse_req_t req, const char *link, int fd, const char *name) {
	string path;
	int dirfd = get_fd_path_at(fd, name, OP_SYMLINK, path);
	return as_user(req, dirfd, path, __func__, [&](){
			return symlinkat(link, dirfd, path.c_str());
		});
}

static int do_mknod(fuse_req_t req, int fd, const char *name, mode_t mode, dev_t rdev) {
	string path;
	int dirfd = get_fd_path_at(fd, name, OP_MKNOD, path);
	return as_user(req, dirfd, path, __func__, [&](){
			return mknodat(dirfd, path.c_str(), mode, rdev);
		});
}

static void mknod_symlink(fuse_req_t req, fuse_ino_t parent,
		const char *name, mode_t mode, dev_t rdev,
		const char *link) {
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	int res;
	auto saverr = ENOMEM;

	if (S_ISDIR(mode))
		res = do_mkdir(req, inode_p.fd, name, mode);
	else if (S_ISLNK(mode))
		res = do_symlink(req, link, inode_p.fd, name);
	else
		res = do_mknod(req, inode_p.fd, name, mode, rdev);
	saverr = errno;
	if (res == -1)
		goto out;

	fuse_entry_param e;
	saverr = do_lookup(inode_p, name, &e);
	if (saverr)
		goto out;

	fuse_reply_entry(req, &e);
	return;

out:
	fuse_reply_fd_err(req, saverr);
}


static void sfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode, dev_t rdev) {
	mknod_symlink(req, parent, name, mode, rdev, nullptr);
}


static void sfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode) {
	mknod_symlink(req, parent, name, S_IFDIR | mode, 0, nullptr);
}


static void sfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
		const char *name) {
	mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}


static int do_link(InodeRef &inode, int dfd, const char *name) {
	auto path = inode.get_path(OP_LINK);
	string newpath;
	int newdirfd = get_fd_path_at(dfd, name, OP_LINK, newpath);
	return linkat(AT_FDCWD, path, newdirfd, newpath.c_str(), AT_SYMLINK_FOLLOW);
}


static void sfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
		const char *name) {
	InodeRef inode(get_inode(ino));
	InodeRef inode_p(get_inode(parent));
	if (inode.error(req) || inode_p.error(req))
		return;

	fuse_entry_param e {};
	e.attr_timeout = fs.timeout;
	e.entry_timeout = fs.timeout;

	auto res = do_link(inode, inode_p.fd, name);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}

	res = fstatat(inode.fd, "", &e.attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	e.ino = ino;
	{
		lock_guard<mutex> g {inode.i->m};
		inode.i->nlookup++;
	}

	fuse_reply_entry(req, &e);
	return;
}


static void sfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	string path;
	int dirfd = get_fd_path_at(inode_p.fd, name, OP_RMDIR, path);
	auto res = unlinkat(dirfd, path.c_str(), AT_REMOVEDIR);
	fuse_reply_err(req, res == -1 ? errno : 0);
}


static void sfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		fuse_ino_t newparent, const char *newname,
		unsigned int flags) {
	InodeRef inode_p(get_inode(parent));
	InodeRef inode_np(get_inode(newparent));
	if (inode_p.error(req) || inode_np.error(req))
		return;

	if (flags) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	string oldpath, newpath;
	int olddirfd = get_fd_path_at(inode_p.fd, name, OP_RENAME, oldpath);
	int newdirfd = get_fd_path_at(inode_np.fd, newname, OP_RENAME, newpath);
	auto res = renameat(olddirfd, oldpath.c_str(), newdirfd, newpath.c_str());
	if (res == -1)
		fuse_reply_err(req, errno);

	// Lookup to update new parent in connectable file handle of moved inode
	fuse_entry_param e;
	auto err = do_lookup(inode_np, newname, &e);
	fuse_reply_err(req, err);
}


static void sfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	string path;
	int dirfd = get_fd_path_at(inode_p.fd, name, OP_UNLINK, path);
	auto res = unlinkat(dirfd, path.c_str(), 0);
	fuse_reply_err(req, res == -1 ? errno : 0);
}


static void forget_one(fuse_ino_t ino, uint64_t n) {
	auto inode_ptr = get_inode(ino);
	Inode &inode = *inode_ptr;
	lock_guard<mutex> g {inode.m};

	if (inode.dead())
		return;

	auto src_ino = inode.ino();
	if (n > inode.nlookup) {
		cerr << "INTERNAL ERROR: Negative lookup count ("
			<< inode.nlookup << " - " << n <<
			") for inode " << src_ino << endl;
		n = inode.nlookup;
	}
	inode.nlookup -= n;
	if (!inode.nlookup) {
		int ninodes;
		{
			lock_guard<mutex> g_fs {fs.mutex};
			// Mark dead inode to protect against racing with lookup
			inode.src_fh.ino = 0;
			fs.inodes.erase(ino);
			ninodes = fs.inodes.size();
		}
		if (fs.debug)
			cerr << "DEBUG: forget: cleaning up inode " << src_ino
				<< " inode count is " << ninodes << endl;
	} else if (fs.debug) {
		cerr << "DEBUG: forget: inode " << src_ino
			<< " lookup count now " << inode.nlookup << endl;
	}
}

static void sfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
	forget_one(ino, nlookup);
	fuse_reply_none(req);
}


static void sfs_forget_multi(fuse_req_t req, size_t count,
		fuse_forget_data *forgets) {
	for (unsigned i = 0; i < count; i++)
		forget_one(forgets[i].ino, forgets[i].nlookup);
	fuse_reply_none(req);
}


static void sfs_readlink(fuse_req_t req, fuse_ino_t ino) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	char buf[PATH_MAX + 1];
	auto res = readlinkat(inode.fd, "", buf, sizeof(buf));
	if (res == -1)
		fuse_reply_err(req, errno);
	else if (res == sizeof(buf))
		fuse_reply_err(req, ENAMETOOLONG);
	else {
		buf[res] = '\0';
		fuse_reply_readlink(req, buf);
	}
}


struct DirHandle : public FileHandle {
	DIR *dp {nullptr};
	off_t offset;

	int get_fd() override { return dirfd(dp); };

	DirHandle() = default;
	DirHandle(const DirHandle&) = delete;
	DirHandle& operator=(const DirHandle&) = delete;

	~DirHandle() {
		if(dp)
			closedir(dp);
	}
};


static DirHandle *get_dir_handle(fuse_file_info *fi)
{
	return reinterpret_cast<DirHandle*>(fi->fh);
}

static void release_dir_handle(fuse_file_info *fi)
{
	auto d = get_dir_handle(fi);
	delete d;
	fi->fh = 0;
}

static void sfs_opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	auto d = new (nothrow) DirHandle;
	if (d == nullptr) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	string path;
	int dirfd = get_fd_path_at(inode.fd, ".", OP_OPENDIR, path);
	auto fd = openat(dirfd, path.c_str(), O_RDONLY);
	if (fd == -1)
		goto out_errno;

	// On success, dir stream takes ownership of fd, so we
	// do not have to close it.
	d->dp = fdopendir(fd);
	if(d->dp == nullptr)
		goto out_errno;

	d->offset = 0;

	fi->fh = reinterpret_cast<uint64_t>(d);
	if (fs.timeout) {
		// TODO: implement "auto_cache" like logic and/or invalidate
		// readdir cache on FAN_DIR_MODIFY
		fi->keep_cache = 1;
		fi->cache_readdir = 1;
	}
	fuse_reply_open(req, fi);
	return;

out_errno:
	auto error = errno;
	delete d;
	if (fd > 0)
		close(fd);
	fuse_reply_fd_err(req, error);
}


static void do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, fuse_file_info *fi, int plus) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	auto d = get_dir_handle(fi);
	char *p;
	auto rem = size;
	int err = 0, count = 0;

	if (fs.debug)
		cerr << "DEBUG: readdir(): started with offset "
			<< offset << endl;

	auto buf = new (nothrow) char[size];
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}
	p = buf;

	if (offset != d->offset) {
		if (fs.debug)
			cerr << "DEBUG: readdir(): seeking to " << offset << endl;
		seekdir(d->dp, offset);
		d->offset = offset;
	}

	while (1) {
		struct dirent *entry;
		errno = 0;
		entry = readdir(d->dp);
		if (!entry) {
			if(errno) {
				err = errno;
				if (fs.debug)
					warn("DEBUG: readdir(): readdir failed with");
				goto error;
			}
			break; // End of stream
		}
		d->offset = entry->d_off;
		if (is_dot_or_dotdot(entry->d_name))
			continue;

		fuse_entry_param e{};
		size_t entsize;
		// With 32bit ino, lookup to encode d_ino from ino+generation
		if (plus || fs.ino32) {
			err = do_lookup(inode, entry->d_name, &e);
			if (err)
				goto error;

			if (plus)
				entsize = fuse_add_direntry_plus(req, p, rem, entry->d_name, &e, entry->d_off);
			else
				entsize = fuse_add_direntry(req, p, rem, entry->d_name, &e.attr, entry->d_off);

			if (entsize > rem) {
				if (fs.debug)
					cerr << "DEBUG: readdir(): buffer full, returning data. " << endl;
				forget_one(e.ino, 1);
				break;
			}
		} else {
			e.attr.st_ino = entry->d_ino;
			e.attr.st_mode = entry->d_type << 12;
			entsize = fuse_add_direntry(req, p, rem, entry->d_name, &e.attr, entry->d_off);

			if (entsize > rem) {
				if (fs.debug)
					cerr << "DEBUG: readdir(): buffer full, returning data. " << endl;
				break;
			}
		}

		p += entsize;
		rem -= entsize;
		count++;
		if (fs.debug) {
			cerr << "DEBUG: readdir(): added to buffer: " << entry->d_name
				<< ", ino " << e.attr.st_ino << ", offset " << entry->d_off << endl;
		}
	}
	err = 0;
error:

	// If there's an error, we can only signal it if we haven't stored
	// any entries yet - otherwise we'd end up with wrong lookup
	// counts for the entries that are already in the buffer. So we
	// return what we've collected until that point.
	if (err && rem == size) {
		fuse_reply_fd_err(req, err);
	} else {
		if (fs.debug)
			cerr << "DEBUG: readdir(): returning " << count
				<< " entries, curr offset " << d->offset << endl;
		fuse_reply_buf(req, buf, size - rem);
	}
	delete[] buf;
	return;
}


static void sfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, fuse_file_info *fi) {
	// operation logging is done in readdir to reduce code duplication
	do_readdir(req, ino, size, offset, fi, 0);
}


static void sfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, fuse_file_info *fi) {
	// operation logging is done in readdir to reduce code duplication
	do_readdir(req, ino, size, offset, fi, 1);
}


static void sfs_releasedir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	(void) ino;
	release_dir_handle(fi);
	fuse_reply_err(req, 0);
}


static int do_create(fuse_req_t req, int fd, const char *name, enum op op,
		     int flags, mode_t mode, bool &redirected) {
	string path;
	auto dirfd = get_fd_path_at(fd, name, op, path);
	redirected = IS_REDIRECETED(dirfd);
	return as_user(req, dirfd, path, __func__, [&](){
			return openat(dirfd, path.c_str(), (flags | O_CREAT) & ~O_NOFOLLOW, mode);
		});
}

static void sfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode, fuse_file_info *fi) {
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	enum op op = redirect_open_op(fi->flags);
	bool redirected;
	auto fd = do_create(req, inode_p.fd, name, op, fi->flags, mode, redirected);
	if (fd == -1) {
		fuse_reply_fd_err(req, errno);
		return;
	}

	auto fh = fd_open(fd, redirected, op, inode_p.folder_id(),
			  inode_p.fd, name, fi->flags);
	if (!fh) {
		fuse_reply_fd_err(req, errno);
		close(fd);
		return;
	}

	fuse_entry_param e;
	auto err = do_lookup(inode_p, name, &e);
	if (err) {
		delete fh;
		fuse_reply_fd_err(req, err);
		return;
	}

	if (fs.rwpassthrough) {
		int passthrough_fh = fuse_passthrough_enable(req, fd);
		if (passthrough_fh > 0)
			fi->passthrough_fh = passthrough_fh;
		else if (fs.debug)
			cerr << "DEBUG: fuse_passthrough_enable returned: "
				<< passthrough_fh << endl;
	}

	fi->fh = reinterpret_cast<uint64_t>(fh);
	fuse_reply_create(req, &e, fi);
}


static void sfs_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
		fuse_file_info *fi) {
	(void) ino;
	int res;
	int fd = get_file_fd(fi);
	if (datasync)
		res = fdatasync(fd);
	else
		res = fsync(fd);
	fuse_reply_err(req, res == -1 ? errno : 0);
}


static int do_open(InodeRef &inode, enum op op, int flags, bool &redirected)
{
	string path;
	auto dirfd = get_fd_path_at(inode.fd, "", op, path, inode.folder_id());
	redirected = IS_REDIRECETED(dirfd);
	return open(path.c_str(), flags & ~O_NOFOLLOW);
}

static void sfs_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	/* With writeback cache, kernel may send read requests even
	   when userspace opened write-only */
	if (fs.wbcache && (fi->flags & O_ACCMODE) == O_WRONLY) {
		fi->flags &= ~O_ACCMODE;
		fi->flags |= O_RDWR;
	}

	/* With writeback cache, O_APPEND is handled by the kernel.  This
	   breaks atomicity (since the file may change in the underlying
	   filesystem, so that the kernel's idea of the end of the file
	   isn't accurate anymore). However, no process should modify the
	   file in the underlying filesystem once it has been read, so
	   this is not a problem. */
	if (fs.wbcache && fi->flags & O_APPEND)
		fi->flags &= ~O_APPEND;

	/* Unfortunately we cannot use inode.fd, because this was opened
	   with O_PATH (so it doesn't allow read/write access). */
	enum op op = redirect_open_op(fi->flags);
	bool redirected;
	auto fd = do_open(inode, op, fi->flags, redirected);
	if (fd == -1) {
		fuse_reply_fd_err(req, errno);
		return;
	}

	auto fh = fd_open(fd, redirected, op, inode.folder_id(),
			  inode.fd, "", fi->flags);
	if (!fh) {
		fuse_reply_fd_err(req, errno);
		close(fd);
		return;
	}

	if (fs.rwpassthrough) {
		int passthrough_fh = fuse_passthrough_enable(req, fd);
		if (passthrough_fh > 0)
			fi->passthrough_fh = passthrough_fh;
		else if (fs.debug)
			cerr << "DEBUG: fuse_passthrough_enable returned: "
				<< passthrough_fh << endl;
	}

	// TODO: implement "auto_cache" logic and/or invalidate file data cache
	// on FAN_MODIFY
	fi->keep_cache = (fs.timeout != 0);
	fi->noflush = (!fs.wbcache && op == OP_OPEN_RO);
	fi->fh = reinterpret_cast<uint64_t>(fh);
	fuse_reply_open(req, fi);
}

static void sfs_release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	(void) ino;
	release_file_handle(fi);
	fuse_reply_err(req, 0);
}


static void sfs_flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
	(void) ino;
	auto res = close(dup(get_file_fd(fi)));
	fuse_reply_err(req, res == -1 ? errno : 0);
}


static void sfs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
		fuse_file_info *fi) {
	(void) ino;
	int res;
	if (datasync)
		res = fdatasync(get_file_fd(fi));
	else
		res = fsync(get_file_fd(fi));
	fuse_reply_err(req, res == -1 ? errno : 0);
}


static void do_read(fuse_req_t req, size_t size, off_t off, fuse_file_info *fi) {

	fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
	buf.buf[0].flags = static_cast<fuse_buf_flags>(
			FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
	buf.buf[0].fd = get_file_fd(fi);
	buf.buf[0].pos = off;

	fuse_reply_data(req, &buf, FUSE_BUF_COPY_FLAGS);
}

static void sfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		fuse_file_info *fi) {
	(void) ino;
	do_read(req, size, off, fi);
}


static void do_write_buf(fuse_req_t req, size_t size, off_t off,
		fuse_bufvec *in_buf, fuse_file_info *fi) {
	fuse_bufvec out_buf = FUSE_BUFVEC_INIT(size);
	out_buf.buf[0].flags = static_cast<fuse_buf_flags>(
			FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
	out_buf.buf[0].fd = get_file_fd(fi);
	out_buf.buf[0].pos = off;

	auto res = fuse_buf_copy(&out_buf, in_buf, FUSE_BUF_COPY_FLAGS);
	if (res < 0)
		fuse_reply_err(req, -res);
	else
		fuse_reply_write(req, (size_t)res);
}


static void sfs_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *in_buf,
		off_t off, fuse_file_info *fi) {
	(void) ino;
	auto size {fuse_buf_size(in_buf)};
	do_write_buf(req, size, off, in_buf, fi);
}


static int do_statfs(InodeRef &inode, struct statvfs *stbuf) {
	return statvfs(inode.get_path(OP_STATFS, true), stbuf);
}

static void sfs_statfs(fuse_req_t req, fuse_ino_t ino) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	struct statvfs stbuf;
	auto res = do_statfs(inode, &stbuf);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_statfs(req, &stbuf);
}


#ifdef HAVE_POSIX_FALLOCATE
static void sfs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
		off_t offset, off_t length, fuse_file_info *fi) {
	(void) ino;
	if (mode) {
		fuse_reply_err(req, EOPNOTSUPP);
		return;
	}

	auto err = posix_fallocate(get_file_fd(fi), offset, length);
	fuse_reply_err(req, err);
}
#endif

static void sfs_flock(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi,
		int op) {
	(void) ino;
	auto res = flock(get_file_fd(fi), op);
	fuse_reply_err(req, res == -1 ? errno : 0);
}


#ifdef HAVE_SETXATTR
const string sys_acl_xattr_prefix = "system.posix_acl";

static bool xattr_starts_with(const char *name, const string &prefix)
{
	return !prefix.empty() &&
		strncmp(name, prefix.c_str(), prefix.size()) == 0;
}
static enum op redirect_xattr_op(enum op op, const char *name)
{
	if (fs.debug)
		cerr << "DEBUG: " << op_name(op) << " " << name << endl;

	// redirect xattr ops for names that match a redirect_xattr_prefix
	for (const auto& prefix : fs.redirect()->xattr_prefixes) {
	    if (xattr_starts_with(name, prefix))
		return OP_REDIRECT;
	}

	// redirect implicit chmod/chown via setfacl
	if (op == OP_SETXATTR && (fs.redirect_op(OP_CHMOD) || fs.redirect_op(OP_CHOWN)) &&
	    xattr_starts_with(name, sys_acl_xattr_prefix))
		return OP_REDIRECT;

	return op;
}

static int do_getxattr(InodeRef& inode, const char *name, char *value,
		size_t size) {
	auto op = redirect_xattr_op(OP_GETXATTR, name);
	return getxattr(inode.get_path(op), name, value, size);
}

static void sfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
		size_t size) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	char *value = nullptr;
	ssize_t ret;
	int saverr;

	if (size) {
		value = new (nothrow) char[size];
		if (value == nullptr) {
			saverr = ENOMEM;
			goto out;
		}

		ret = do_getxattr(inode, name, value, size);
		if (ret == -1)
			goto out_err;
		saverr = 0;
		if (ret == 0)
			goto out;

		fuse_reply_buf(req, value, ret);
	} else {
		ret = do_getxattr(inode, name, nullptr, 0);
		if (ret == -1)
			goto out_err;

		fuse_reply_xattr(req, ret);
	}
out_free:
	delete[] value;
	return;

out_err:
	saverr = errno;
out:
	fuse_reply_err(req, saverr);
	goto out_free;
}


static int do_listxattr(InodeRef& inode, char *value, size_t size) {
	return listxattr(inode.get_path(OP_GETXATTR), value, size);
}

static void sfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	char *value = nullptr;
	ssize_t ret;
	int saverr;

	if (size) {
		value = new (nothrow) char[size];
		if (value == nullptr) {
			saverr = ENOMEM;
			goto out;
		}

		ret = do_listxattr(inode, value, size);
		if (ret == -1)
			goto out_err;
		saverr = 0;
		if (ret == 0)
			goto out;

		fuse_reply_buf(req, value, ret);
	} else {
		ret = do_listxattr(inode, nullptr, 0);
		if (ret == -1)
			goto out_err;

		fuse_reply_xattr(req, ret);
	}
out_free:
	delete[] value;
	return;
out_err:
	saverr = errno;
out:
	fuse_reply_err(req, saverr);
	goto out_free;
}


static int do_setxattr(InodeRef& inode, const char *name,
		const char *value, size_t size, int flags) {
	auto op = redirect_xattr_op(OP_SETXATTR, name);
	return setxattr(inode.get_path(op), name, value, size, flags);
}

static void sfs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
		const char *value, size_t size, int flags) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	ssize_t ret;
	int saverr;

	ret = do_setxattr(inode, name, value, size, flags);
	saverr = ret == -1 ? errno : 0;

	fuse_reply_err(req, saverr);
}


static void sfs_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	auto op = redirect_xattr_op(OP_SETXATTR, name);
	ssize_t ret;
	int saverr;

	ret = removexattr(inode.get_path(op), name);
	saverr = ret == -1 ? errno : 0;

	fuse_reply_err(req, saverr);
}
#endif

#ifndef HAVE_COPY_FILE_RANGE
static loff_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
			      loff_t *off_out, size_t len, unsigned int flags)
{
	return syscall(__NR_copy_file_range, fd_in, off_in, fd_out,
			off_out, len, flags);
}
#endif

static void sfs_copy_file_range(fuse_req_t req,
		fuse_ino_t, off_t off_in, struct fuse_file_info *fi_in,
		fuse_ino_t, off_t off_out, struct fuse_file_info *fi_out,
		size_t len, int flags)
{
	ssize_t res;
	auto fh_in = get_file(fi_in);
	auto fh_out = get_file(fi_out);
	auto fd_in = fh_in->get_fd();
	auto fd_out = fh_out->get_fd();
	auto redirect = fs.redirect_op(OP_COPY);

	// Get redirected fds from File struct
	if (redirect) {
		fd_in = fh_in->get_redirect_fd();
		if (fd_in == -1) {
			fuse_reply_fd_err(req, EBADF);
			return;
		}

		fd_out = fh_out->get_redirect_fd();
		if (fd_out == -1) {
			fuse_reply_fd_err(req, EBADF);
			return;
		}
	}

	res = copy_file_range(fd_in, &off_in, fd_out, &off_out, len, flags);
	if (res < 0)
		fuse_reply_err(req, errno);
	else
		fuse_reply_write(req, res);
}


static void assign_operations(fuse_lowlevel_ops &sfs_oper) {
	sfs_oper.init = sfs_init;
	sfs_oper.lookup = sfs_lookup;
	sfs_oper.mkdir = sfs_mkdir;
	sfs_oper.mknod = sfs_mknod;
	sfs_oper.symlink = sfs_symlink;
	sfs_oper.link = sfs_link;
	sfs_oper.unlink = sfs_unlink;
	sfs_oper.rmdir = sfs_rmdir;
	sfs_oper.rename = sfs_rename;
	sfs_oper.forget = sfs_forget;
	sfs_oper.forget_multi = sfs_forget_multi;
	sfs_oper.getattr = sfs_getattr;
	sfs_oper.setattr = sfs_setattr;
	sfs_oper.readlink = sfs_readlink;
	sfs_oper.opendir = sfs_opendir;
	sfs_oper.readdir = sfs_readdir;
	sfs_oper.readdirplus = sfs_readdirplus;
	sfs_oper.releasedir = sfs_releasedir;
	sfs_oper.fsyncdir = sfs_fsyncdir;
	sfs_oper.create = sfs_create;
	sfs_oper.open = sfs_open;
	sfs_oper.release = sfs_release;
	sfs_oper.flush = sfs_flush;
	sfs_oper.fsync = sfs_fsync;
	sfs_oper.read = sfs_read;
	sfs_oper.write_buf = sfs_write_buf;
	sfs_oper.statfs = sfs_statfs;
#ifdef HAVE_POSIX_FALLOCATE
	sfs_oper.fallocate = sfs_fallocate;
#endif
	sfs_oper.flock = sfs_flock;
#ifdef HAVE_SETXATTR
	sfs_oper.setxattr = sfs_setxattr;
	sfs_oper.getxattr = sfs_getxattr;
	sfs_oper.listxattr = sfs_listxattr;
	sfs_oper.removexattr = sfs_removexattr;
#endif
	sfs_oper.copy_file_range = sfs_copy_file_range;
}

static void print_usage(cxxopts::Options& parser, char *prog_name) {
	cout << "\nUsage: " << prog_name << " [options] <source> <mountpoint>\n";
	// Strip everything before the option list from the
	// default help string.
	auto help = parser.help({"", "fuse"});
	std::cout << std::endl << " options:"
		<< help.substr(help.find("\n\n") + 1, string::npos) << std::endl;
}

static cxxopts::ParseResult parse_wrapper(cxxopts::Options& parser, int& argc, char**& argv) {
	try {
		return parser.parse(argc, argv);
	} catch (cxxopts::option_not_exists_exception& exc) {
		std::cout << argv[0] << ": " << exc.what() << std::endl;
		print_usage(parser, argv[0]);
		exit(2);
	}
}


static cxxopts::ParseResult parse_options(int &argc, char **argv) {
	cxxopts::Options opt_parser(argv[0]);
	opt_parser.allow_unrecognised_options();
	opt_parser.add_options()
		("debug", "Enable filesystem debug messages")
		("help", "Print help")
		("redirect", "Redirect all operations")
		("redirect_path", "Path to access tiered files",
		 cxxopts::value<std::string>(), "PATH")
		("config_file", "Config file reloaded on SIGHUP",
		 cxxopts::value<std::string>()->default_value(CONFIG_FILE), "FILE");

	opt_parser.add_options("fuse")
		("debug-fuse", "Enable libfuse debug messages")
		("nocache", "Disable all caching")
		("wbcache", "Enable writeback cache")
		("nosplice", "Do not use splice(2) to transfer data")
		("norwpassthrough", "Do not use pass-through mode for read/write")
		("single", "Run single-threaded");

	// FIXME: Find a better way to limit the try clause to just
	// opt_parser.parse() (cf. https://github.com/jarro2783/cxxopts/issues/146)
	auto options = parse_wrapper(opt_parser, argc, argv);

	if (options.count("help")) {
		print_usage(opt_parser, argv[0]);
		exit(0);

	} else if (argc < 3) {
		std::cout << argv[0] << ": invalid number of arguments\n";
		print_usage(opt_parser, argv[0]);
		exit(2);
	}

	fs.nosplice = options.count("nosplice") != 0;
	if (options.count("nocache") == 0)
		fs.wbcache = options.count("wbcache") != 0;
	fs.rwpassthrough = options.count("norwpassthrough") == 0;
	auto rp = realpath(argv[1], NULL);
	if (!rp) {
		cerr << "realpath(" << argv[1] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "source is " << rp << endl;
	fs.source = rp;

	string redirect_path;
	if (options.count("redirect_path")) {
		redirect_path = options["redirect_path"].as<std::string>();
	} else if (argc > 3 && argv[3][0] != '-') {
		redirect_path = argv[3];
	}
	if (!redirect_path.empty()) {
		rp = realpath(redirect_path.c_str(), NULL);
		if (!rp)
			err(1, "ERROR: realpath(\"%s\")", redirect_path.c_str());
		cout << "redirect path is " << rp << endl;
		fs.redirect_path = rp;
	}

	if (options.count("config_file")) {
		fs.config_file = options["config_file"].as<std::string>();
	} else if (argc > 4 && argv[4][0] != '-') {
		fs.config_file = argv[4];
	}
	cout << "config file is " << fs.config_file << endl;

	return options;
}

static bool parseConfigLine(const string &line, string &name, string &value)
{
	/* regex explained:
	 * \s* Match 0+ whitespace chars
	 * ( Capture group 1
	 * [^\s=]+ Match any char except =,space using a negated character class
	 * ) Close group
	 * \s* Match 0+ whitespace chars
	 * = Match literally
	 * \s* Match 0+ whitespace chars
	 * ( Capture group 2
	 * [^\s#]+ Match any char except whitespace char or #
	 * ) Close group
	 * .* Anything including and after space or #
	 */
	static const std::regex rgx(R"(\s*([^\s=]+)\s*=\s*([^\s#]+).*)");
	std::smatch matches;
	std::regex_match(line, matches, rgx);

	if (matches.size() < 2)
		return false;

	name = matches[1].str();
	value = matches[2].str();

	return true;
}

static Redirect *read_config_file()
{
	if (fs.redirect_path.empty()) {
		// Redirect disabled with mount options
		return nullptr;
	}

	std::ifstream cFile(fs.config_file);
	if (!cFile.is_open()) {
		if (fs.config_file != CONFIG_FILE)
			cerr << "ERROR: Failed to open config file " << fs.config_file << endl;
		return nullptr;
	}

	Redirect *redirect = new (nothrow) Redirect();
	if (!redirect) {
		cerr << "ERROR: Allocate new config failed." << endl;
		return nullptr;
	}

	bool debug = false;
	std::string line;
	while (getline(cFile, line)) {
		string name, value;

		if (!parseConfigLine(line, name, value))
			continue;

		std::cout << name << " = " << value << std::endl;
		if (name == "debug") {
			debug = std::stoi(value);
		} else if (name == "redirect_read_xattr") {
			// Implies also redirect_readdir_xattr
			redirect->read_xattr = value;
			redirect->readdir_xattr = value;
			redirect->set_op(OP_OPEN_RO);
			redirect->set_op(OP_OPENDIR);
			redirect->set_op(OP_LOOKUP);
		} else if (name == "redirect_readdir_xattr") {
			redirect->readdir_xattr = value;
			redirect->set_op(OP_OPENDIR);
			redirect->set_op(OP_LOOKUP);
		} else if (name == "redirect_write_xattr") {
			redirect->write_xattr = value;
			redirect->set_op(OP_OPEN_RW);
		} else if (name == "redirect_write_folder_id") {
			redirect->set_folder_id(value);
			redirect->set_op(OP_OPEN_RW);
		} else if (name == "redirect_xattr_prefix") {
			redirect->xattr_prefixes.push_back(value);
		} else if (name == "redirect_op") {
			redirect->set_op(value);
		}
	}

	fs.debug = debug;

	return redirect;
}

static void reload_config(int)
{
	// Request config reload
	fs.reset_config();
}

static void set_signal_handler()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = reload_config;
	sigemptyset(&(sa.sa_mask));

	if (sigaction(SIGHUP, &sa, NULL) == -1)
		warn("WARNING: sigaction() failed with");
}

static void maximize_fd_limit() {
	struct rlimit lim {};
	auto res = getrlimit(RLIMIT_NOFILE, &lim);
	if (res != 0) {
		warn("WARNING: getrlimit() failed with");
		return;
	}
	fs.max_keepfd = lim.rlim_cur/2;
	lim.rlim_cur = lim.rlim_max;
	res = setrlimit(RLIMIT_NOFILE, &lim);
	if (res != 0) {
		warn("WARNING: setrlimit() failed with");
		return;
	}
	fs.max_keepfd = lim.rlim_cur/2;
	cout << "max keepfd = " << fs.max_keepfd << endl;
}


int main(int argc, char *argv[]) {

	// Parse command line options
	auto options {parse_options(argc, argv)};

	// Read defaults from config file
	auto r = fs.redirect();
	// Re-load config file on SIGHUP
	set_signal_handler();
	// These mount option settings are cleared on config file reload
	if (options.count("redirect"))
		r->set_op(OP_ALL);
	if (options.count("debug"))
		fs.debug = true;

	// We need an fd for every dentry in our the filesystem that the
	// kernel knows about. This is way more than most processes need,
	// so try to get rid of any resource softlimit.
	maximize_fd_limit();

	// Initialize filesystem root
	fs.init_root();
	fs.timeout = options.count("nocache") ? 0 : 1.0;

	// Initialize fuse
	auto ret = -1;
	fuse_args args = FUSE_ARGS_INIT(0, nullptr);
	if (fuse_opt_add_arg(&args, argv[0]) ||
			fuse_opt_add_arg(&args, "-o") ||
			fuse_opt_add_arg(&args, "nosuid,nodev,allow_other,default_permissions,fsname=cachegw,subtype=cachegw") ||
			(options.count("debug-fuse") && fuse_opt_add_arg(&args, "-odebug")))
		errx(3, "ERROR: Out of memory");

	fuse_lowlevel_ops sfs_oper {};
	assign_operations(sfs_oper);
	auto se = fuse_session_new(&args, &sfs_oper, sizeof(sfs_oper), &fs);
	if (se == nullptr)
		goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;

	// Don't apply umask, use modes exactly as specified
	umask(0);

	// Mount and run main loop
	struct fuse_loop_config loop_config;
	loop_config.clone_fd = 1;
	loop_config.max_idle_threads = 10;
	if (fuse_session_mount(se, argv[2]) != 0)
		goto err_out3;
	if (options.count("single"))
		ret = fuse_session_loop(se);
	else
		ret = fuse_session_loop_mt(se, &loop_config);

	fuse_session_unmount(se);

err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}

