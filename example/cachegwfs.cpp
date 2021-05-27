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

struct Inode {
	int _fd {0}; // > 0 for long lived O_PATH fd; -1 for open_by_handle
	bool is_symlink {false};
	ino_t src_ino {0};
	uint32_t gen {0};
	uint64_t nlookup {0};
	std::mutex m;

	bool dead() { return !src_ino; }

	// Delete copy constructor and assignments. We could implement
	// move if we need it.
	Inode() = default;
	Inode(const Inode&) = delete;
	Inode(Inode&& inode) = delete;
	Inode& operator=(Inode&& inode) = delete;
	Inode& operator=(const Inode&) = delete;

	void keepfd(fd_guard& newfd) {
		// Upgrade short lived fd to long lived fd in inode cache
		_fd = newfd._fd;
		newfd._fd = -1;
	}

	~Inode() {
		if (_fd > 0)
			close(_fd);
	}
};

// Maps files in the source directory tree to inodes
typedef shared_ptr<Inode> InodePtr;
typedef std::map<ino_t, InodePtr> InodeMap;

enum op {
	OP_REDIRECT, // Force redirect
	OP_OPEN_RO,
	OP_OPEN_RW,
	OP_STATFS,
	OP_CREATE,
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
	OP_OTHER,
};

const std::map<enum op, const char *> op_names = {
	{ OP_OPEN_RO, "open_ro" },
	{ OP_OPEN_RW, "open_rw" },
	{ OP_SYMLINK, "symlink" },
	{ OP_STATFS, "statfs" },
	{ OP_CREATE, "create" },
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
	vector<string> xattr_prefixes;
	std::set<enum op> ops; // fs operations to redirect

	bool test_op(enum op op) {
		return ops.count(op) > 0;
	}
	void set_op(enum op op) {
		ops.insert(op);
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
};

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
	std::string config_file;
	size_t blocksize;
	dev_t src_dev;
	bool nosplice;
	bool nocache;
	bool wbcache;
	bool bulkstat {true};

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
		return op == OP_REDIRECT || r->test_op(op);
	}

private:
	atomic_flag config_is_valid {ATOMIC_FLAG_INIT};
	shared_ptr<Redirect> _redirect;
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


#define XFS_FILEID_TYPE_64FLAG  0x80    /* NFS fileid has 64bit inodes */
#define XFS_FILEID_INO64_GEN (1 | XFS_FILEID_TYPE_64FLAG)

struct xfs_fid64 {
	uint64_t ino;
	uint32_t gen;
} __attribute__((packed));

struct xfs_fh {
	struct file_handle fh;
	struct xfs_fid64 fid;

	xfs_fh() {
		fh.handle_bytes = sizeof(fid);
		fid.ino = fid.gen = 0;
	}

	xfs_fh(ino_t ino, uint32_t gen)
	{
		// Construct xfs file handle to get inode with or without generation
		fh.handle_bytes = sizeof(fid);
		fh.handle_type = gen ? XFS_FILEID_INO64_GEN : XFS_FILEID_TYPE_64FLAG;
		fid.ino = ino;
		fid.gen = gen;
	}
};

// Check if this is an empty place holder (a.k.a stub file).
// See: https://github.com/github/libprojfs/blob/master/docs/design.md#extended-attributes
static bool should_redirect_fd(const char *procname, enum op op)
{
	bool rw;
	if (op == OP_OPEN_RO)
		rw = false;
	else if (op == OP_OPEN_RW)
		rw = true;
	else
		return true;

	auto r = fs.redirect();
	const string &redirect_xattr = rw ? r->write_xattr : r->read_xattr;
	if (redirect_xattr.empty())
		return true;

	return getxattr(procname, redirect_xattr.c_str(), NULL, 0) > 0;
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

static int get_fd_path_at(int dirfd, const char *name, enum op op, string &outpath)
{
	char procname[64];
	sprintf(procname, "/proc/self/fd/%i", dirfd);
	char linkname[PATH_MAX];
	int n = 0;
	bool redirect_op = fs.redirect_op(op);

	if (fs.debug || redirect_op) {
		n = readlink(procname, linkname, PATH_MAX);
	}
	if (n > 0 && fs.debug) {
		linkname[n] = 0;
		cerr << "DEBUG: " << op_name(op) << " " << procname
			<< " -> " << linkname << endl;
	}
	int prefix = fs.source.size();
	if (redirect_op && prefix && n >= prefix &&
	    !memcmp(fs.source.c_str(), linkname, prefix) &&
	    should_redirect_fd(procname, op)) {
		if (fs.debug)
			cerr << "DEBUG: redirect " << op_name(op)
				<< " |=> " << linkname + prefix << endl;
		outpath = fs.redirect_path;
		outpath.append(linkname + prefix, n - prefix);
		if (*name) {
			outpath.append("/");
			outpath.append(name);
		}
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

// Convert fd to path for system calls that do not take an O_PATH fd
static string get_fd_path(int fd, enum op op = OP_OTHER)
{
	string path;
	(void)get_fd_path_at(fd, "", op, path);
	return path;
}

static uint32_t xfs_bulkstat_gen(__u64 ino)
{
	// Method only works for XFS and requires SYS_CAP_ADMIN
	if (!fs.bulkstat)
		return 0;

	__s32 count = 0;
	struct xfs_bstat bstat = { };
	struct xfs_fsop_bulkreq breq = {
		.lastip = &ino,
		.icount = 1,
		.ubuffer = (void *)&bstat,
		.ocount = &count,
	};

	if (ioctl(fs.root->_fd, XFS_IOC_FSBULKSTAT_SINGLE, &breq) != 0) {
		cerr << "WARNING: failed to bulkstat inode " << ino << ", errno=" << errno << endl;
		// Try open by handle with zero generation
		return 0;
	}

	if (fs.debug) {
		cerr << "DEBUG: open_by_ino(): ino=" << ino << ", count=" << count
			<< ", bs_ino=" << bstat.bs_ino  << ", bs_gen=" << bstat.bs_gen <<  endl;
	}

	return bstat.bs_gen;
}

static int open_by_ino(InodePtr inode)
{
	auto ino = inode->src_ino;
	auto gen = inode->gen;

	// We usually use the gen that we stored during lookup
	// Only in the special case of lookup(ino, ".") (i.e. recover
	// an NFS file handle after server restart), we need to resort
	// to bulkstat which may or may not be supported by filesystem
	if (!gen)
		gen = xfs_bulkstat_gen(ino);

	// open by real or fake XFS file handle
	struct xfs_fh fake_xfs_fh{ino, gen};

	int fd = open_by_handle_at(fs.root->_fd, &fake_xfs_fh.fh, O_PATH);
	if (fd < 0)
		return fd;

	if (!gen && fs.bulkstat) {
		// We failed to get gen from ino using bulkstat but we could open by handle
		// with zero gen (using XFS kernel patch) - do not try to use bulkstat again
		cerr << "WARNING: kernel has open by ino - bulkstat disabled." << endl;
		fs.bulkstat = false;
	}

	if (fs.debug)
		get_fd_path(fd);

	return fd;
}

// Short lived reference of inode to keep fd open
struct InodeRef {
	InodePtr i;
	int fd {-1}; // Short lived O_PATH fd
	const bool is_symlink;
	const ino_t src_ino;

	// Delete copy constructor and assignments. We could implement
	// move if we need it.
	InodeRef() = delete;
	InodeRef(const InodeRef&) = delete;
	InodeRef(InodeRef&& inode) = delete;
	InodeRef& operator=(InodeRef&& inode) = delete;
	InodeRef& operator=(const InodeRef&) = delete;

	InodeRef(InodePtr inode) : i(inode),
		is_symlink(inode->is_symlink), src_ino(inode->src_ino)
	{
		if (i->dead())
			return;

		fd = i->_fd;
		if (fd == -1) {
			fd = open_by_ino(inode);
		}
		if (fd == -1) {
			fd = -errno;
			cerr << "INFO: failed to open fd for inode " << src_ino
				<< ", err=" << fd  << ", gen=" << inode->gen <<  endl;
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

	~InodeRef() {
		if (fd > 0 && fd != i->_fd)
			close(fd);
	}
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
	const bool redirected;

	int get_fd() override { return _fd; };

	File() = delete;
	File(const File&) = delete;
	File& operator=(const File&) = delete;

	File(int fd, int dirfd) : _fd(fd), redirected(dirfd == AT_FDCWD) {
		// cachegw manager takes an exclusive lock before making file a stub
		if (!redirected && flock(fd, LOCK_SH | LOCK_NB) == -1) {
			_fd = -errno;
			cerr << "INFO: file is locked for read/write access." << endl;
		}
		if (fs.debug)
			cerr << "DEBUG: open(): fd=" << _fd << endl;
	}
	~File() {
		if (fs.debug)
			cerr << "DEBUG: close(): fd=" << _fd << endl;
		if (_fd > 0)
			close(_fd);
	}
};

static FileHandle *get_file_handle(fuse_file_info *fi) {
	return reinterpret_cast<FileHandle*>(fi->fh);
}

static int get_file_fd(fuse_file_info *fi) {
	return get_file_handle(fi)->get_fd();
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


#ifdef HAVE_UTIMENSAT
static int utimensat_empty_nofollow(InodeRef& inode,
		const struct timespec *tv) {
	if (inode.is_symlink) {
		/*
		 * Does not work on current kernels, but may in the future:
		 * https://marc.info/?l=linux-kernel&m=154158217810354&w=2
		 */
		auto res = utimensat(inode.fd, "", tv, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
		if (res == -1 && errno == EINVAL) {
			/* Sorry, no race free way to set times on symlink. */
			errno = EPERM;
		}
		return res;
	}

	return utimensat(AT_FDCWD, get_fd_path(inode.fd, OP_UTIMENS).c_str(), tv, 0);
}
#endif


static void do_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		int valid, struct fuse_file_info* fi) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	int ifd = inode.fd;
	int res;

	if (valid & FUSE_SET_ATTR_MODE) {
		if (fi) {
			res = fchmod(get_file_fd(fi), attr->st_mode);
		} else {
			res = chmod(get_fd_path(ifd, OP_CHMOD).c_str(), attr->st_mode);
		}
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
		uid_t uid = (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : NULL_UID;
		gid_t gid = (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : NULL_GID;

		res = fchownat(AT_FDCWD, get_fd_path(ifd, OP_CHOWN).c_str(), uid, gid, 0);
		if (res == -1)
			goto out_err;
	}
	if (valid & FUSE_SET_ATTR_SIZE) {
		if (fi) {
			res = ftruncate(get_file_fd(fi), attr->st_size);
		} else {
			res = truncate(get_fd_path(ifd, OP_TRUNCATE).c_str(), attr->st_size);
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
			res = utimensat_empty_nofollow(inode, tv);
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
			<< ", parent=" << parent.src_ino << endl;
	memset(e, 0, sizeof(*e));
	e->attr_timeout = fs.timeout;
	e->entry_timeout = fs.timeout;

	int newfd;
	if (strcmp(name, ".") == 0) {
		newfd = open_by_ino(parent.i);
	} else if (strcmp(name, "..") == 0) {
		newfd = openat(parent.fd, name, O_PATH | O_NOFOLLOW);
	} else {
		// Check if reading parent directory should be redirected
		// and lookup child in redirect path before lookup in source path
		// to trigger populate of place holder directory
		string path;
		int dirfd = get_fd_path_at(parent.fd, name, OP_OPEN_RO, path);
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
	res = name_to_handle_at(newfd, "", &xfs_fh.fh, &mount_id, AT_EMPTY_PATH);
	if (res == -1) {
		auto saveerr = errno;
		if (fs.debug)
			cerr << "DEBUG: lookup(): name_to_handle_at failed" << endl;
		return saveerr;
	}

	auto src_ino = e->attr.st_ino;
	auto root_ino = fs.root->src_ino;

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
	} else if (xfs_fh.fh.handle_type != XFS_FILEID_INO64_GEN) {
		cerr << "WARNING: Source directory expected to be XFS." << endl;
		return ENOTSUP;
	} else if (src_ino != xfs_fh.fid.ino) {
		cerr << "ERROR: Source st_ino " << src_ino <<
			" and file handle ino " << xfs_fh.fid.ino << " mismatch." << endl;
		return EIO;
	}

	e->ino = src_ino;
	e->generation = xfs_fh.fid.gen;

#ifdef DEBUG_INTERNAL_ERROR_UNKNOWN_INO
	// Fake lookup success without inserting to inodes map.
	// Listing root dir works, but stat on entries returns ENOENT.
	return 0;
#endif

	unique_lock<mutex> fs_lock {fs.mutex};
	auto iter = fs.inodes.find(src_ino);
	bool found = (iter != fs.inodes.end());
	InodePtr inode_ptr;

	if (found && iter->second->gen != xfs_fh.fid.gen) {
		cerr << "INFO: lookup(): inode " << src_ino
			<< " generation " << e->generation
			<< " mismatch - reused inode." << endl;
	}
	if (found) {
		inode_ptr = iter->second;
	} else try {
		fs.inodes[src_ino].reset(new Inode());
		inode_ptr = fs.inodes[src_ino];
	} catch (std::bad_alloc&) {
		return ENOMEM;
	}

#ifdef DEBUG_INTERNAL_ERROR_OPEN_BY_INO
	// Fake lookup success by inserting a bad inode into map.
	// Listing root dir works, but stat on non-subdir entries or on
	// 2nd level subdirs returns ESTALE.
	// 1st level subdirs keep an open fd, so don't need open_by_ino()
	// on next lookup.
	src_ino = FUSE_ROOT_ID;
#endif

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
				<< "; gen = " << xfs_fh.fid.gen << ",fd = " << inode._fd << endl;
		lock_guard<mutex> g {inode.m};
		inode.gen = xfs_fh.fid.gen;
		// Maybe update long lived fd if opened initially by handle
		if (inode._fd == -1 && parent.src_ino == root_ino && S_ISDIR(e->attr.st_mode))
			inode.keepfd(newfd_g);
		inode.nlookup++;
	} else { // no existing inode
		/* This is just here to make Helgrind happy. It violates the
		   lock ordering requirement (inode.m must be acquired before
		   fs.mutex), but this is of no consequence because at this
		   point no other thread has access to the inode mutex */
		lock_guard<mutex> g {inode.m};
		inode.src_ino = src_ino;
		inode.gen = xfs_fh.fid.gen;
		inode.is_symlink = S_ISLNK(e->attr.st_mode);
		inode.nlookup = 1;
		if (parent.src_ino == root_ino && S_ISDIR(e->attr.st_mode)) {
			// Hold long lived fd for subdirs of root
			inode.keepfd(newfd_g);
		} else {
			// Mark inode for open_by_handle
			inode._fd = -1;
		}
		fs_lock.unlock();

		if (fs.debug)
			cerr << "DEBUG: lookup(): created userspace inode " << src_ino
				<< "; gen = " << xfs_fh.fid.gen << ",fd = " << inode._fd << endl;
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
		// request to open by FUSE file handle
		inode_p->_fd = 0;
		inode_p->src_ino = parent;
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
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors." << endl;
		fuse_reply_err(req, err);
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
	return as_user(req, fd, name, __func__, [&](){
			return mkdirat(dirfd, path.c_str(), mode);
		});
}

static int do_symlink(fuse_req_t req, const char *link, int fd, const char *name) {
	string path;
	int dirfd = get_fd_path_at(fd, name, OP_SYMLINK, path);
	return as_user(req, fd, name, __func__, [&](){
			return symlinkat(link, dirfd, path.c_str());
		});
}

static int do_mknod(fuse_req_t req, int fd, const char *name, mode_t mode, dev_t rdev) {
	string path;
	int dirfd = get_fd_path_at(fd, name, OP_MKNOD, path);
	return as_user(req, fd, name, __func__, [&](){
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
	if (saverr == ENFILE || saverr == EMFILE)
		cerr << "ERROR: Reached maximum number of file descriptors." << endl;
	fuse_reply_err(req, saverr);
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


static int linkat_empty_nofollow(fuse_req_t, InodeRef& inode, int dfd, const char *name) {
	if (inode.is_symlink) {
		if (fs.redirect_op(OP_LINK)) {
			errno = EOPNOTSUPP;
			return -1;
		}
		auto res = linkat(inode.fd, "", dfd, name, AT_EMPTY_PATH);
		if (res == -1 && (errno == ENOENT || errno == EINVAL)) {
			/* Sorry, no race free way to hard-link a symlink. */
			errno = EOPNOTSUPP;
		}
		return res;
	}

	string path = get_fd_path(inode.fd, OP_LINK);
	string newpath;
	int newdirfd = get_fd_path_at(dfd, name, OP_LINK, newpath);
	return linkat(AT_FDCWD, path.c_str(), newdirfd, newpath.c_str(), AT_SYMLINK_FOLLOW);
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

	auto res = linkat_empty_nofollow(req, inode, inode_p.fd, name);
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

	lock_guard<mutex> g {inode_p.i->m};
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
	fuse_reply_err(req, res == -1 ? errno : 0);
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

	if (n > inode.nlookup) {
		cerr << "INTERNAL ERROR: Negative lookup count ("
			<< inode.nlookup << " - " << n <<
			") for inode " << inode.src_ino << endl;
		n = inode.nlookup;
	}
	inode.nlookup -= n;
	if (!inode.nlookup) {
		auto src_ino = inode.src_ino;
		int ninodes;
		{
			lock_guard<mutex> g_fs {fs.mutex};
			// Mark dead inode to protect against racing with lookup
			inode.src_ino = 0;
			fs.inodes.erase(ino);
			ninodes = fs.inodes.size();
		}
		if (fs.debug)
			cerr << "DEBUG: forget: cleaning up inode " << src_ino
				<< " inode count is " << ninodes << endl;
	} else if (fs.debug) {
		cerr << "DEBUG: forget: inode " << inode.src_ino
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


static DirHandle *get_dir_handle(fuse_file_info *fi) {
	return reinterpret_cast<DirHandle*>(fi->fh);
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

	// Make Helgrind happy - it can't know that there's an implicit
	// synchronization due to the fact that other threads cannot
	// access d until we've called fuse_reply_*.
	lock_guard<mutex> g {inode.i->m};

	string path;
	int dirfd = get_fd_path_at(inode.fd, ".", OP_OPEN_RO, path);
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
	if (error == ENFILE || error == EMFILE)
		cerr << "ERROR: Reached maximum number of file descriptors." << endl;
	fuse_reply_err(req, error);
}


static bool is_dot_or_dotdot(const char *name) {
	return name[0] == '.' &&
		(name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}


static void do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, fuse_file_info *fi, int plus) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	auto d = get_dir_handle(fi);
	lock_guard<mutex> g {inode.i->m};
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
		if(plus) {
			err = do_lookup(inode, entry->d_name, &e);
			if (err)
				goto error;
			entsize = fuse_add_direntry_plus(req, p, rem, entry->d_name, &e, entry->d_off);

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
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors." << endl;
		fuse_reply_err(req, err);
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


static void sfs_releasedir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
	(void) ino;
	auto d = get_dir_handle(fi);
	delete d;
	fuse_reply_err(req, 0);
}


static int do_create(fuse_req_t req, int fd, const char *name, int flags, mode_t mode, int &dirfd) {
	string path;
	dirfd = get_fd_path_at(fd, name, OP_CREATE, path);
	return as_user(req, fd, name, __func__, [&](){
			return openat(dirfd, path.c_str(), (flags | O_CREAT) & ~O_NOFOLLOW, mode);
		});
}

static void sfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode, fuse_file_info *fi) {
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	int dirfd;
	auto fd = do_create(req, inode_p.fd, name, fi->flags, mode, dirfd);
	if (fd == -1) {
		auto err = errno;
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors." << endl;
		fuse_reply_err(req, err);
		return;
	}

	auto fh = new (nothrow) File(fd, dirfd);
	if (fh == nullptr || fh->_fd < 0) {
		delete fh;
		close(fd);
		fuse_reply_err(req, fh ? -fh->_fd : ENOMEM);
		return;
	}

	fuse_entry_param e;
	auto err = do_lookup(inode_p, name, &e);
	if (err) {
		delete fh;
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors." << endl;
		fuse_reply_err(req, err);
		return;
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
	enum op op = (fi->flags & O_ACCMODE) == O_RDONLY ? OP_OPEN_RO : OP_OPEN_RW;
	string path;
	auto dirfd = get_fd_path_at(inode.fd, "", op, path);
	auto fd = open(path.c_str(), fi->flags & ~O_NOFOLLOW);
	if (fd == -1) {
		auto err = errno;
		if (err == ENFILE || err == EMFILE)
			cerr << "ERROR: Reached maximum number of file descriptors." << endl;
		fuse_reply_err(req, err);
		return;
	}

	auto fh = new (nothrow) File(fd, dirfd);
	if (fh == nullptr || fh->_fd < 0) {
		delete fh;
		close(fd);
		fuse_reply_err(req, fh ? -fh->_fd : ENOMEM);
		return;
	}

	// TODO: implement "auto_cache" logic and/or invalidate file data cache
	// on FAN_MODIFY
	fi->keep_cache = (fs.timeout != 0);
	fi->fh = reinterpret_cast<uint64_t>(fh);
	fuse_reply_open(req, fi);
}


static void sfs_release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
	(void) ino;
	auto fh = get_file_handle(fi);
	delete fh;
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


static int do_statfs(int fd, struct statvfs *stbuf) {
	if (fs.redirect_op(OP_STATFS)) {
		string path = get_fd_path(fd, OP_STATFS);
		return statvfs(path.c_str(), stbuf);
	} else {
		return fstatvfs(fd, stbuf);
	}
}

static void sfs_statfs(fuse_req_t req, fuse_ino_t ino) {
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	struct statvfs stbuf;
	auto res = do_statfs(inode.fd, &stbuf);
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
	return getxattr(get_fd_path(inode.fd, op).c_str(), name, value, size);
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
	return listxattr(get_fd_path(inode.fd, OP_GETXATTR).c_str(), value, size);
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
	return setxattr(get_fd_path(inode.fd, op).c_str(), name, value, size, flags);
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

	if (inode.is_symlink) {
		/* Sorry, no race free way to setxattr on symlink. */
		saverr = ENOTSUP;
		goto out;
	}

	ret = removexattr(get_fd_path(inode.fd, op).c_str(), name);
	saverr = ret == -1 ? errno : 0;

out:
	fuse_reply_err(req, saverr);
}
#endif


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
}

static void print_usage(char *prog_name) {
	cout << "Usage: " << prog_name << " --help\n"
		<< "       " << prog_name << " [options] <source> <mountpoint> [<redirect path> [<conf file>]]\n";
}

static cxxopts::ParseResult parse_wrapper(cxxopts::Options& parser, int& argc, char**& argv) {
	try {
		return parser.parse(argc, argv);
	} catch (cxxopts::option_not_exists_exception& exc) {
		std::cout << argv[0] << ": " << exc.what() << std::endl;
		print_usage(argv[0]);
		exit(2);
	}
}


#define CONFIG_FILE "/etc/cachegwfs.conf"

static cxxopts::ParseResult parse_options(int &argc, char **argv) {
	cxxopts::Options opt_parser(argv[0]);
	opt_parser.add_options()
		("debug", "Enable filesystem debug messages")
		("debug-fuse", "Enable libfuse debug messages")
		("help", "Print help")
		("nocache", "Disable all caching")
		("wbcache", "Enable writeback cache")
		("nosplice", "Do not use splice(2) to transfer data")
		("single", "Run single-threaded");

	// FIXME: Find a better way to limit the try clause to just
	// opt_parser.parse() (cf. https://github.com/jarro2783/cxxopts/issues/146)
	auto options = parse_wrapper(opt_parser, argc, argv);

	if (options.count("help")) {
		print_usage(argv[0]);
		// Strip everything before the option list from the
		// default help string.
		auto help = opt_parser.help();
		std::cout << std::endl << "options:"
			<< help.substr(help.find("\n\n") + 1, string::npos);
		exit(0);

	} else if (argc < 3) {
		std::cout << argv[0] << ": invalid number of arguments\n";
		print_usage(argv[0]);
		exit(2);
	}

	if (options.count("debug"))
		fs.debug = true;
	fs.nosplice = options.count("nosplice") != 0;
	if (options.count("nocache") == 0)
		fs.wbcache = options.count("wbcache") != 0;
	auto rp = realpath(argv[1], NULL);
	if (!rp) {
		cerr << "realpath(" << argv[1] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "source is " << rp << endl;
	fs.source = rp;
	if (argc > 3) {
		rp = realpath(argv[3], NULL);
		if (!rp) {
			cerr << "realpath(" << argv[3] << ") failed: " << strerror(errno) << endl;
			exit(1);
		}
		cout << "redirect is " << rp << endl;
		fs.redirect_path = rp;
	}

	fs.config_file = std::string {argc > 4 ? argv[4] : CONFIG_FILE};

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
		cerr << "ERROR: Open config file failed." << endl;
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
			redirect->read_xattr = value;
			redirect->set_op(OP_OPEN_RO);
		} else if (name == "redirect_write_xattr") {
			redirect->write_xattr = value;
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
	lim.rlim_cur = lim.rlim_max;
	res = setrlimit(RLIMIT_NOFILE, &lim);
	if (res != 0)
		warn("WARNING: setrlimit() failed with");
}


int main(int argc, char *argv[]) {

	// Parse command line options
	auto options {parse_options(argc, argv)};

	// Read defaults from config file
	(void)fs.redirect();
	// Re-load config file on SIGHUP
	set_signal_handler();

	// We need an fd for every dentry in our the filesystem that the
	// kernel knows about. This is way more than most processes need,
	// so try to get rid of any resource softlimit.
	maximize_fd_limit();

	// Initialize filesystem root
	fs.root.reset(new Inode());
	fs.root->nlookup = 9999;
	fs.root->is_symlink = false;
	fs.timeout = options.count("nocache") ? 0 : 1.0;

	struct stat stat;
	auto ret = lstat(fs.source.c_str(), &stat);
	if (ret == -1)
		err(1, "ERROR: failed to stat source (\"%s\")", fs.source.c_str());
	if (!S_ISDIR(stat.st_mode))
		errx(1, "ERROR: source is not a directory");
	fs.src_dev = stat.st_dev;
	fs.root->src_ino = stat.st_ino;

	// Used as mount_fd for open_by_handle_at() - O_PATH fd is not enough
	fs.root->_fd = open(fs.source.c_str(), O_DIRECTORY | O_RDONLY);
	if (fs.root->_fd == -1)
		err(1, "ERROR: open(\"%s\")", fs.source.c_str());

	// Initialize fuse
	fuse_args args = FUSE_ARGS_INIT(0, nullptr);
	if (fuse_opt_add_arg(&args, argv[0]) ||
			fuse_opt_add_arg(&args, "-o") ||
			fuse_opt_add_arg(&args, "allow_other,default_permissions,fsname=cachegw,subtype=cachegw") ||
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
	loop_config.clone_fd = 0;
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
