/*
  FUSE passthrough: FUSE passthrough library

  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2017       Nikolaus Rath <Nikolaus@rath.org>
  Copyright (C) 2018       Valve, Inc
  Copyright (C) 2021-2024  CTERA Networks

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

/** @file
 *
 * Core implementation of a FUSE passthrough filesystem.
 *
 * When the mirrored source filesystem is xfs or ext4, the implementation
 * supports persistent NFS file handles - the FUSE server can be restarted
 * without breaking NFS client file handles.
 *
 * ## Source code ##
 */

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 12)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// C includes
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse.h>
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
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <fstream>
#include <thread>
#include <iomanip>
#include <atomic>
#include <set>

#include "fuse_passthrough.h"

using namespace std;


#define FS_FILEID_INO32_GEN	1
#define FS_FILEID_INO32_GEN_PARENT 2
#define FS_FILEID_INO64_GEN	0x81
#define FS_FILEID_INO64_GEN_PARENT 0x82
#define FS_FILEID_TYPE_MASK	0xFF

// Flag used to request connectable file handle (requires a kernel patch)
#ifndef AT_HANDLE_CONNECTABLE
#define AT_HANDLE_CONNECTABLE	0x002	/* Request a connectable file handle */
#endif

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
		return ino(fh);
	}
	void encode(struct file_handle &fh, ino_t ino, uint32_t gen) const override {
		// Construct xfs file handle from ino/gen for -o inode32
		fh.handle_bytes = offsetof(struct fid32, parent_ino);
		fh.handle_type = FS_FILEID_INO32_GEN;
		((struct fid32 *)fh.f_handle)->ino = ino;
		((struct fid32 *)fh.f_handle)->gen = gen;
	}
	bool is_connectable(const struct file_handle &fh) const override {
		return (fh.handle_type & FS_FILEID_TYPE_MASK) ==
			FS_FILEID_INO32_GEN_PARENT;
	}
	bool get_parent_fh(const struct file_handle &fh,
			   struct file_handle &parent_fh) const override {
		if (!is_connectable(fh))
			return false;

		// Construct parent file handle from connectable fh
		parent_fh.handle_bytes = offsetof(struct fid32, parent_ino);
		parent_fh.handle_type = FS_FILEID_INO32_GEN;
		((struct fid32 *)parent_fh.f_handle)->ino =
			((struct fid32 *)fh.f_handle)->parent_ino;
		((struct fid32 *)parent_fh.f_handle)->gen =
			((struct fid32 *)fh.f_handle)->parent_gen;
		return true;
	}
	bool make_connectable(struct file_handle &fh,
			      const struct file_handle &parent_fh) const override {
		if (is_connectable(fh))
			return true;

		if (fh.handle_type != FS_FILEID_INO32_GEN ||
		    parent_fh.handle_type != FS_FILEID_INO32_GEN)
			return false;

		// Combine parent+child non-connectable 32bit ino file handles
		// into a connectable file handle
		fh.handle_bytes = sizeof(struct fid32);
		fh.handle_type = FS_FILEID_INO32_GEN_PARENT;
		((struct fid32 *)fh.f_handle)->parent_ino =
			((struct fid32 *)parent_fh.f_handle)->ino;
		((struct fid32 *)fh.f_handle)->parent_gen =
			((struct fid32 *)parent_fh.f_handle)->gen;
		return true;
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
		fh.handle_type = FS_FILEID_INO64_GEN;
		((struct fid64 *)fh.f_handle)->ino = ino;
		((struct fid64 *)fh.f_handle)->gen = gen;
	}
	bool is_connectable(const struct file_handle &fh) const override {
		return (fh.handle_type & FS_FILEID_TYPE_MASK) ==
			FS_FILEID_INO64_GEN_PARENT;
	}
	bool get_parent_fh(const struct file_handle &fh,
			   struct file_handle &parent_fh) const override {
		if (!is_connectable(fh))
			return false;

		// Construct parent file handle from connectable fh
		parent_fh.handle_bytes = offsetof(struct fid64, parent_ino);
		parent_fh.handle_type = FS_FILEID_INO64_GEN;
		((struct fid64 *)parent_fh.f_handle)->ino =
			((struct fid64 *)fh.f_handle)->parent_ino;
		((struct fid64 *)parent_fh.f_handle)->gen =
			((struct fid64 *)fh.f_handle)->parent_gen;
		return true;
	}
	bool make_connectable(struct file_handle &fh,
			      const struct file_handle &parent_fh) const override {
		if (is_connectable(fh))
			return true;

		if (fh.handle_type != FS_FILEID_INO64_GEN ||
		    parent_fh.handle_type != FS_FILEID_INO64_GEN)
			return false;

		// Combine parent+child non-connectable 64bit ino file handles
		// into a connectable file handle
		fh.handle_bytes = sizeof(struct fid64);
		fh.handle_type = FS_FILEID_INO64_GEN_PARENT;
		((struct fid64 *)fh.f_handle)->parent_ino =
			((struct fid64 *)parent_fh.f_handle)->ino;
		((struct fid64 *)fh.f_handle)->parent_gen =
			((struct fid64 *)parent_fh.f_handle)->gen;
		return true;
	}
} fid64_encoder;

struct xfs_fh {
	struct file_handle fh;
	union {
		struct fid64 fid64;
		struct fid32 fid32;
	} fid;

	xfs_fh(ino_t src_ino, uint32_t src_gen = 0) {
		// Initialize file handle buffer to detect -o inode64/inode32
		fh.handle_bytes = sizeof(fid);
		fh.handle_type = 0;
		memset((char *)&fid, 0, sizeof(fid));
		// Remember src_ino in case file handles are not supported
		nodeid = ino = src_ino;
		gen = src_gen;
	}

	// Return an fh encoder to use for the file_handle read from fs
	// FS_FILEID_INO32_GEN could be xfs with -o inode32, ext4 or another fs
	// FS_FILEID_INO64_GEN is most likely xfs
	const fh_encoder *get_encoder() const {
		// Mask out FILEID flags (e.g. FILEID_IS_CONNECTABLE)
		switch (fh.handle_type & FS_FILEID_TYPE_MASK) {
			case FS_FILEID_INO32_GEN:
			case FS_FILEID_INO32_GEN_PARENT:
				return &fid32_encoder;
			case FS_FILEID_INO64_GEN:
			case FS_FILEID_INO64_GEN_PARENT:
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
	ftype_dir,
	ftype_regular,
	ftype_symlink,
	ftype_special,
};

struct fuse_module_states {
	fuse_module_states(int num_modules) : states(num_modules) {}
	~fuse_module_states() {};

	fuse_state_t& get_state(const fuse_passthrough_module &module) {
		return states.at(module.idx - 1);
	}

private:
	vector<fuse_state_t> states;
};

struct Inode {
	int _fd {0}; // > 0 for long lived O_PATH fd; -1 for open_by_handle
	int _ftype {ftype_unknown};
	xfs_fh src_fh {0};
	uint64_t nlookup {0};
	// Allow each module to store/fetch state in inode
	fuse_module_states module_states;
	mutex m;

	ino_t ino() { return src_fh.ino; }
	ino_t gen() { return src_fh.gen; }
	ino_t nodeid() { return src_fh.nodeid; }
	bool dead() { return !src_fh.ino; }

	Inode(int num_modules) : module_states(num_modules) {}
	// Delete copy constructor and assignments. We could implement
	// move if we need it.
	Inode(const Inode&) = delete;
	Inode(Inode&& inode) = delete;
	Inode& operator=(Inode&& inode) = delete;
	Inode& operator=(const Inode&) = delete;

	void keepfd(fd_guard& newfd) {
		// Upgrade short lived fd to long lived fd in inode cache
		_fd = newfd._fd;
		newfd._fd = -1;
	}

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

	~Inode() {
		if (_fd > 0)
			close(_fd);
	}
};

// Maps files in the source directory tree to inodes
typedef shared_ptr<Inode> InodePtr;
typedef map<ino_t, InodePtr> InodeMap;

struct Fs : public fuse_passthrough_module {
	// Must be acquired *after* any Inode.m locks.
	mutex m;
	InodeMap inodes; // protected by mutex
	InodePtr root;
	uid_t uid;
	gid_t gid;
	dev_t src_dev;
	bool ino32 {false};
	bool fhandles {true};
	bool bulkstat {true};
	int num_modules;
	int at_connectable {0};

	Fs() : fuse_passthrough_module("default") {
		// Get own credentials
		uid = geteuid();
		gid = getegid();
		// Initialize a dead inode
		inodes[0].reset(new Inode(0));
	}

	const char *source() { return opts.source.c_str(); }
	void init_root();
	int open_by_fh(xfs_fh &fh);
	uint32_t xfs_bulkstat_gen(__u64 ino);
	const fh_encoder *get_encoder() const { return encoder; }
	bool decode(xfs_fh &xfh);
	bool encode(xfs_fh &xfh);

private:
	void get_root_fh(ino_t src_ino);

	const fh_encoder *encoder{NULL};
	int _bulkstat_fd{-1};
};
static Fs fs{};

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


#define call_op(op) call_module_next_op(fs, op)


#define FUSE_BUF_COPY_FLAGS			\
	(fs.opts.nosplice ?			\
	 FUSE_BUF_NO_SPLICE :			\
	 static_cast<fuse_buf_copy_flags>(0))

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


fuse_empty_path_at::fuse_empty_path_at(fuse_req_t req, fuse_inode &inode) :
	fuse_path_at(req, inode, "")
{
	if (!fs.fhandles || !fs.opts.connected_fd)
	       return;

	// For empty path, try to make sure that we have an fd with known path
	if (reconnect())
	       return;

	if (fs.debug())
		cerr << "WARNING: inode " << inode.ino() << ", fd " << inode.get_fd()
			<< " path is unknown" << endl;
}

bool fuse_path_at::reconnect() const
{
	if (is_connected())
	       return true;

	auto encoder = fs.get_encoder();
	auto const &fh = *inode().get_file_handle();
	xfs_fh dir_fh{0};
	if (!encoder->get_parent_fh(fh, dir_fh.fh))
		return false;

	auto ino = inode().ino();
	auto dirfd = open_by_handle_at(fs.root->_fd, &dir_fh.fh, O_DIRECTORY);
	if (dirfd < 0) {
		if (fs.debug())
			cerr << "ERROR: failed to open by parent fh of inode "
				<< ino << ", errno=" << errno << endl;
		return false;
	}

	DIR *dp = fdopendir(dirfd);
	if (dp == NULL) {
		close(dirfd);
		return false;
	}

	// look for the child in the parent directory
	while(1) {
		struct dirent *de;
		de = readdir(dp);
		if (!de)
			break;
		if (de->d_ino == ino) {
			// child found - look it up to connect its dentry in cache
			faccessat(dirfd, de->d_name, F_OK, AT_SYMLINK_NOFOLLOW);
			if (fs.debug())
				cerr << "DEBUG: found child '" << de->d_name
					<< "' with inode " << ino << endl;
			break;
		}
	}
	closedir(dp);

	// close the disconnected fd and reopen the fd hoping to get a connected alias
	inode().close_fd();
	inode().open_fd();

	return is_connected();
}

bool fuse_path_at::is_connected() const
{
	char linkname[3];
	int n = 0;

	// Path is connected if it is a non-empty path relative to a dirfd
	if (!empty() && !is_magic())
		return true;

	n = readlink(proc_path(), linkname, 3);
	// magic link to "/" means disconnected (unknown) path
	// NOTE that a known unlinked path is also connected, e.g.:
	// -> "/path/to/file (deleted)"
	return n > 2 || strncmp(linkname, "/", 2);
}

// Prints fuse path argument.
// Unless path is relative to CWD also prints the dirfd symlink path.
void fuse_path_at::print_fd_path(const char *caller) const
{
	char linkname[PATH_MAX];
	int n = 0;

	if (dirfd() != AT_FDCWD) {
		n = readlink(proc_path(), linkname, PATH_MAX);
	}

	string fd_path;
	if (n > 0) {
		linkname[n] = 0;
		fd_path.append(" @ ");
		fd_path.append(proc_path());
		fd_path.append(" -> ");
		fd_path.append(linkname);
	}
	cerr << "DEBUG: " << caller << "(" << path() << ")"
		<< fd_path << endl;
}

void __trace_fd_path_at(const fuse_path_at &at, const char *caller)
{
	if (fs.debug())
		at.print_fd_path(caller);
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
		_bulkstat_fd = openat(root->_fd, ".", O_DIRECTORY);
	if (_bulkstat_fd < 0 ||
	    ioctl(_bulkstat_fd, XFS_IOC_FSBULKSTAT_SINGLE, &breq) != 0) {
		auto saverr = errno;
		cerr << "INFO: failed to bulkstat inode " << ino << ", errno=" << errno << endl;
		errno = saverr;
		// Try open by handle with zero generation
		return 0;
	}

	if (debug()) {
		cerr << "DEBUG: xfs_bulkstat_gen(): ino=" << ino << ", count=" << count
			<< ", bs_ino=" << bstat.bs_ino  << ", bs_gen=" << bstat.bs_gen <<  endl;
	}

	return bstat.bs_gen;
}

int Fs::open_by_fh(xfs_fh &fh)
{
	if (!fhandles) {
		errno = ESTALE;
		return -1;
	}

	int fd = open_by_handle_at(root->_fd, &fh.fh, O_PATH);
	if (at_connectable && fd < 0 && errno == ESTALE &&
	    fh.fh.handle_type & ~FS_FILEID_TYPE_MASK) {
		// In case we were trying to open a connectable file handle,
		// we may get ESTALE if file was moved to another parent.
		// Reconstruct a non-connectale file handle from <ino;gen>
		// and try to open an fd which may have an unknown path.
		xfs_fh fid{fh.ino, fh.gen};
		fs.encode(fid);
		fd = open_by_handle_at(root->_fd, &fid.fh, O_PATH);
	}
	if (fd < 0)
		return fd;

	return fd;
}

void Fs::get_root_fh(ino_t src_ino)
{
	int mount_id;
	struct xfs_fh xfs_fh{src_ino};
	at_connectable = fs.opts.connected_fd ? AT_HANDLE_CONNECTABLE : 0;
retry:
	auto ret = name_to_handle_at(root->_fd, "", &xfs_fh.fh, &mount_id,
				     AT_EMPTY_PATH | at_connectable);
	if (ret < 0 && at_connectable) {
		// Maybe connectable fh not supported - retry with non-connectable
		cout << "INFO: connectable file handles not supported by kernel" << endl;
		at_connectable = 0;
		goto retry;
	}

	encoder = xfs_fh.get_encoder();
	if (ret < 0 || !encoder || !decode(xfs_fh) || src_ino != xfs_fh.ino) {
		// Will keep open O_PATH fd instead of open_by_handle()
		fhandles = false;
		at_connectable = 0;
		warn("WARNING: source filesystem file handle type not supported");
	} else {
		root->src_fh = xfs_fh;
		// Auto detect xfs with -o inode32 (or ext4)
		ino32 = (encoder->ino_size() == sizeof(uint32_t));
		// bulkstat support is an indication of xfs
		bulkstat = xfs_bulkstat_gen(src_ino);
		if (!bulkstat && errno == EPERM)
			errx(1, "ERROR: insufficient privileges");
		cout << "INFO: source filesystem looks like "
			<< ((bulkstat || !ino32) ? "xfs" : "ext4")
			<< " -o inode" << (ino32 ? "32" : "64") << endl;
	}
}

void Fs::init_root()
{
	root.reset(new Inode(fs.num_modules));
	root->nlookup = 9999;

	struct stat stat;
	auto ret = lstat(source(), &stat);
	if (ret == -1)
		err(1, "ERROR: failed to stat source (\"%s\")", source());
	if (!S_ISDIR(stat.st_mode))
		errx(1, "ERROR: source is not a directory");
	src_dev = stat.st_dev;
	root->_ftype = ftype_dir;
	// Used as mount_fd for open_by_handle_at() - O_PATH fd is not enough
	root->_fd = open(source(), O_DIRECTORY | O_RDONLY);
	if (root->_fd == -1)
		err(1, "ERROR: open(\"%s\")", source());

	if (fs.opts.keep_fd)
		fhandles = false;
	else
		get_root_fh(stat.st_ino);

	// We never need to open root fd by fh
	root->src_fh.ino = stat.st_ino;
	root->src_fh.nodeid = FUSE_ROOT_ID;
}

// Short lived reference of inode to keep fd open
struct InodeRef : fuse_inode {
	int fd {-1}; // Short lived O_PATH fd
	InodePtr i;

	int get_fd() const override { return fd; }
	fuse_state_t& get_state(const fuse_passthrough_module &module) {
		return i->module_states.get_state(module);
	}
	ino_t ino() const override { return i->ino(); }
	ino_t gen() const override { return i->gen(); }
	ino_t nodeid() const override { return i->nodeid(); }
	file_handle *get_file_handle() const override { return &i->src_fh.fh; }

	bool is_dir() const override {
		return i->_ftype == ftype_dir;
	}
	bool is_regular() const override {
		return i->_ftype == ftype_regular;
	}
	bool is_symlink() const override {
		return i->_ftype == ftype_symlink;
	}
	bool is_special() const override {
		return i->_ftype == ftype_special;
	}
	bool is_dead() const override { return i->dead(); }
	bool is_root() const override { return i == fs.root; }

	// Delete copy constructor and assignments. We could implement
	// move if we need it.
	InodeRef() = delete;
	InodeRef(const InodeRef&) = delete;
	InodeRef(InodeRef&& inode) = delete;
	InodeRef& operator=(InodeRef&& inode) = delete;
	InodeRef& operator=(const InodeRef&) = delete;

	InodeRef(InodePtr inode, bool openfd = true) : i(inode)
	{
		if (i->dead())
			return;

		if (openfd)
			open_fd();
		else
			fd = 0;
	}

	void open_fd() override {
		fd = i->_fd;
		if (fd == -1) {
			fd = fs.open_by_fh(i->src_fh);
		}
		if (fd == -1) {
			fd = -errno;
			cerr << "INFO: failed to open fd for inode "
				<< ino() << endl;
		}
	}

	void close_fd() override {
		// Only close the short lived fd
		if (fd > 0 && fd != i->_fd) {
			close(fd);
			fd = -1;
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
		close_fd();
	}
};

static InodePtr get_inode(fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return fs.root;

	lock_guard<mutex> g_fs {fs.m};
	auto iter = fs.inodes.find(ino);

	if (iter == fs.inodes.end()) {
		cerr << "INTERNAL ERROR: Unknown inode " << ino << endl;
		// return a "dead" inode
		return fs.inodes[0];
	}
	return iter->second;
}

bool get_module_inode_state(const fuse_passthrough_module &module,
			    fuse_ino_t ino, fuse_state_t &ret_state,
			    fuse_fill_state_t filler, void *data)
{
	// Open a short lived O_PATH fd to be used by filler
	InodeRef inode(get_inode(ino), !!filler);
	if (inode.is_dead())
		return false;

	lock_guard<mutex> g {inode.i->m};
	fuse_state_t& state = inode.get_state(module);

	// Initialize a new state or update an existing state
	if (filler && !filler(inode, state, data))
		return false;

	ret_state = state;
	return true;
}

bool set_module_inode_state(const fuse_passthrough_module &module,
			    fuse_ino_t ino, const fuse_state_t &new_state,
			    bool excl)
{
	InodeRef inode(get_inode(ino), false);
	if (inode.is_dead())
		return false;

	lock_guard<mutex> g {inode.i->m};
	fuse_state_t &state = inode.get_state(module);

	if (excl && state)
		return false;

	state = new_state;
	return true;
}

bool clear_module_inode_state(const fuse_passthrough_module &module,
			      fuse_ino_t ino)
{
	InodeRef inode(get_inode(ino), false);
	if (inode.is_dead())
		return false;

	lock_guard<mutex> g {inode.i->m};
	fuse_state_t& state = inode.get_state(module);
	if (!state)
		return false;

	state = nullptr;
	return true;
}


struct File : public fuse_file {
	int _fd {-1};

	int get_fd() override { return _fd; };
	fuse_state_t& get_state(const fuse_passthrough_module &module) {
		return module_states.get_state(module);
	}

	File() = delete;
	File(const File&) = delete;
	File& operator=(const File&) = delete;

	File(int fd, int num_modules) : _fd(fd) ,module_states(num_modules) {
		if (fs.debug())
			cerr << "DEBUG: open(): fd=" << _fd << endl;
	}
	~File() {
		if (fs.debug())
			cerr << "DEBUG: close(): fd=" << _fd << endl;
		if (_fd > 0)
			close(_fd);
	}

private:
	// Allow each module to store/fetch state in file
	fuse_module_states module_states;
};

static void fuse_reply_fd_err(fuse_req_t req, int err)
{
	if (err == ENFILE || err == EMFILE)
		cerr << "ERROR: Reached maximum number of file descriptors." << endl;
	fuse_reply_err(req, err);
}

static void fuse_reply_errno(fuse_req_t req, int res)
{
	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void pfs_init(void *userdata, fuse_conn_info *conn)
{
	(void)userdata;
	if (conn->capable & FUSE_CAP_EXPORT_SUPPORT)
		conn->want |= FUSE_CAP_EXPORT_SUPPORT;

	if (fs.opts.wbcache && conn->capable & FUSE_CAP_WRITEBACK_CACHE)
		conn->want |= FUSE_CAP_WRITEBACK_CACHE;

	if (conn->capable & FUSE_CAP_FLOCK_LOCKS)
		conn->want |= FUSE_CAP_FLOCK_LOCKS;

	if (conn->capable & FUSE_CAP_POSIX_ACL)
		conn->want |= FUSE_CAP_POSIX_ACL;

	if (fs.opts.nosplice) {
		// FUSE_CAP_SPLICE_READ is enabled in libfuse3 by default,
		// see do_init() in in fuse_lowlevel.c
		// Just unset both, in case FUSE_CAP_SPLICE_WRITE would also
		// get enabled by default.
		conn->want &= ~FUSE_CAP_SPLICE_READ;
		conn->want &= ~FUSE_CAP_SPLICE_WRITE;
	} else {
		if (conn->capable & FUSE_CAP_SPLICE_WRITE)
			conn->want |= FUSE_CAP_SPLICE_WRITE;
		if (conn->capable & FUSE_CAP_SPLICE_READ)
			conn->want |= FUSE_CAP_SPLICE_READ;
	}
}

static int do_getattr(const fuse_path_at &at, struct stat *attr, fuse_file_info *fi)
{
	if (fi)
		return fstat(get_file_fd(fi), attr);

	return fstatat(at.dirfd(), at.path(), attr, at.flags());
}

static void pfs_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	(void)fi;
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_empty_path_at at(req, inode);
	struct stat attr;
	auto res = call_op(getattr)(at, &attr, fi);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	fuse_reply_attr(req, &attr, fs.opts.attr_timeout);
}

static int do_chmod(const fuse_path_at &in, mode_t mode, fuse_file_info *fi)
{
	if (fi)
		return fchmod(get_file_fd(fi), mode);

	// Convert empty path to magic symlink
	fuse_path_at_cwd out(in);
	// AT_SYMLINK_NOFOLLOW not implemented
	return fchmodat(out.dirfd(), out.path(), mode, 0);
}

static int do_chown(const fuse_path_at &at, uid_t uid, gid_t gid, fuse_file_info *fi)
{
	(void)fi;
	return fchownat(at.dirfd(), at.path(), uid, gid, at.flags());
}

static int do_truncate(const fuse_path_at &in, off_t size, fuse_file_info *fi)
{
	if (fi)
		return ftruncate(get_file_fd(fi), size);

	// Convert empty path to magic symlink
	fuse_path_at_cwd out(in);
	if (out.empty()) {
		errno = EINVAL;
		return -1;
	}
	return truncate(out.path(), size);
}

static int do_utimens(const fuse_path_at &in, const struct timespec tv[2],
		      struct fuse_file_info *fi)
{
	if (fi) {
		return futimens(get_file_fd(fi), tv);
	} else {
#ifdef HAVE_UTIMENSAT
		// Convert empty path to magic symlink
		fuse_path_at_cwd out(in);
		return utimensat(out.dirfd(), out.path(), tv, out.flags());
#else
		errno = EOPNOTSUPP;
		return -1;
#endif
	}
}

static void pfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			int valid, struct fuse_file_info* fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	auto c = fuse_req_ctx(req);
	fuse_empty_path_at at(req, inode);
	int res;

	if (valid & FUSE_SET_ATTR_MODE) {
		Cred cred(c->uid, c->gid);
		res = call_op(chmod)(at, attr->st_mode, fi);
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
		Cred cred(c->uid, c->gid);
		uid_t uid = (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : NULL_UID;
		gid_t gid = (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : NULL_GID;

		res = call_op(chown)(at, uid, gid, fi);
		if (res == -1)
			goto out_err;
	}
	if (valid & FUSE_SET_ATTR_SIZE) {
		res = call_op(truncate)(at, attr->st_size, fi);
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		Cred cred(c->uid, c->gid);
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

		res = call_op(utimens)(at, tv, fi);
		if (res == -1)
			goto out_err;
	}
	return pfs_getattr(req, ino, fi);

out_err:
	fuse_reply_err(req, errno);
}

static int __do_lookup(const fuse_path_at &at, const char *name, fuse_entry_param *e)
{
	memset(e, 0, sizeof(*e));
	e->attr_timeout = fs.opts.attr_timeout;
	e->entry_timeout = fs.opts.entry_timeout;

	auto dirfd = at.dirfd();
	int newfd;
	// In the case of "."/"..", the parent of the lookup result is unknown
	fuse_ino_t parent_ino = 0;
	if (strcmp(name, ".") == 0) {
		newfd = dup(dirfd);
	} else if (strcmp(name, "..") == 0) {
		newfd = openat(dirfd, name, O_PATH | O_NOFOLLOW);
	} else {
		newfd = openat(dirfd, name, O_PATH | O_NOFOLLOW);
		parent_ino = at.inode().ino();
	}
	if (newfd == -1)
		return errno;

	fd_guard newfd_g(newfd);
	auto res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		auto saveerr = errno;
		if (fs.debug())
			cerr << "DEBUG: lookup(): fstatat failed" << endl;
		return saveerr;
	}

	auto src_ino = e->attr.st_ino;
	auto root_ino = fs.root->ino();

	int mount_id;
	struct xfs_fh xfs_fh{src_ino};
	if (fs.fhandles) {
		res = name_to_handle_at(newfd, "", &xfs_fh.fh, &mount_id,
					AT_EMPTY_PATH | fs.at_connectable);
		if (res == -1) {
			auto saveerr = errno;
			if (fs.debug())
				cerr << "DEBUG: lookup(): name_to_handle_at failed" << endl;
			return saveerr;
		}
		if (!fs.decode(xfs_fh) && fs.debug())
			cerr << "DEBUG: lookup(): failed to decode file handle" << endl;
	}

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
	} else if (src_ino != xfs_fh.ino) {
		cerr << "ERROR: Source st_ino " << src_ino <<
			" and file handle ino " << xfs_fh.ino << " mismatch." << endl;
		return EIO;
	}

	e->ino = xfs_fh.nodeid;
	e->generation = xfs_fh.gen;

	unique_lock<mutex> fs_lock {fs.m};
	auto iter = fs.inodes.find(e->ino);
	bool found = (iter != fs.inodes.end());
	InodePtr inode_ptr;

	if (found) {
		inode_ptr = iter->second;
	} else try {
		fs.inodes[e->ino].reset(new Inode(fs.num_modules));
		inode_ptr = fs.inodes[e->ino];
	} catch (bad_alloc&) {
		return ENOMEM;
	}

	auto is_dir = S_ISDIR(e->attr.st_mode);
	// Hold long lived fd in inode if requested or if open_by_handle() is not supported
	// and always keep long lived fd for subdirs of root
	auto keep_fd = fs.opts.keep_fd || !fs.fhandles || (at.inode().is_root() && is_dir);
	// For non-dir looked up by name, store a connectable fh with parent,
	// so that we can use it later to open an fd with a known path
	auto want_connectable = fs.opts.connected_fd && fs.fhandles && parent_ino && !is_dir;

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
		if (fs.debug())
			cerr << "DEBUG: lookup(): inode " << src_ino << " (userspace) already known"
				<< "; gen = " << xfs_fh.gen << ",fd = " << inode._fd << endl;
		lock_guard<mutex> g {inode.m};
		if (inode.gen() != xfs_fh.gen) {
			if (fs.debug())
				cerr << "DEBUG: lookup(): inode " << src_ino
					<< " generation " << inode.gen()
					<< " mismatch - reused inode." << endl;
			inode.src_fh = xfs_fh;
		}
		// Update parent on lookup by name, because inode may have been moved
		// or inode may have been reconnected after it was found by LOOKUP "."
		auto encoder = fs.get_encoder();
		if (want_connectable &&
		    parent_ino != encoder->parent_ino(inode.src_fh.fh) &&
		    encoder->make_connectable(xfs_fh.fh, *(at.inode().get_file_handle()))) {
			if (fs.debug())
				cerr << "DEBUG: lookup(): inode " << src_ino
					<< " parent " << parent_ino
                                        << " updated." << endl;
			inode.src_fh = xfs_fh;
		}
		// Maybe update long lived fd if inode was initialized by lookup(".")
		if (inode._fd == -1 && keep_fd)
			inode.keepfd(newfd_g);
		inode.nlookup++;
	} else { // no existing inode
		/* This is just here to make Helgrind happy. It violates the
		   lock ordering requirement (inode.m must be acquired before fs.m),
		   but this is of no consequence because at this point no other
		   thread has access to the inode mutex */
		lock_guard<mutex> g {inode.m};
		inode.set_ftype(e->attr.st_mode);
		inode.src_fh = xfs_fh;
		inode.nlookup = 1;
		if (keep_fd) {
			// Hold long lived fd in inode
			inode.keepfd(newfd_g);
		} else {
			// Mark inode for open_by_handle()
			inode._fd = -1;
		}
		fs_lock.unlock();

		if (fs.debug())
			cerr << "DEBUG: lookup(): created userspace inode " << src_ino
				<< "; gen = " << xfs_fh.gen << ",fd = " << inode._fd << endl;
	}

	return 0;
}

static int do_lookup(const fuse_path_at &at, fuse_entry_param *e)
{
	auto err = __do_lookup(at, at.path(), e);
	if (err) {
		errno = err;
		return -1;
	}
	return 0;
}

static void pfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fuse_entry_param e {};
	InodePtr inode_p;

	if (fs.debug())
		cerr << "DEBUG: lookup(): name=" << name
			<< ", parent=" << parent << endl;

	if (strcmp(name, ".") == 0) {
		auto i = new (nothrow) Inode(fs.num_modules);
		if (!i) {
			fuse_reply_err(req, ENOMEM);
			return;
		}
		inode_p.reset(i);
		// Request to open disconnected inode by FUSE file handle
		// FUSE LOOKUP(ino, ".") does not pass the generation
		inode_p->_fd = -1;
		xfs_fh &fh = inode_p->src_fh;
		fh.nodeid = fh.ino = parent;
		// With XFS, we try to use bulkstat to get generation from ino
		if (fs.bulkstat)
			fh.gen = fs.xfs_bulkstat_gen(parent);
		// Reconstruct file handle from <ino;gen>
		if (fs.fhandles)
			fs.encode(fh);
	} else {
		inode_p = get_inode(parent);
	}

	InodeRef inode_ref(inode_p);
	if (inode_ref.error(req))
		return;

	fuse_path_at at(req, inode_ref, name);
	auto res = call_op(lookup)(at, &e);
	if (!res) {
		fuse_reply_entry(req, &e);
	} else if (errno != ENOENT) {
		fuse_reply_fd_err(req, errno);
	} else {
		e.attr_timeout = fs.opts.attr_timeout;
		e.entry_timeout = fs.opts.entry_timeout;
		e.ino = e.attr.st_ino = 0;
		fuse_reply_entry(req, &e);
	}
}

static tuple<bool, gid_t, gid_t> get_sgid_and_gids(const fuse_path_at &at)
{
	struct stat st;

	// The parent
	if (fstatat(at.dirfd(), "", &st,
		    AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) == -1)
	{
		cerr << "ERROR: stat parent of new file: " << strerror(errno) << ". " <<
			"Ignoring SGID if exist and chowning also group" << endl;

		return {false, -1, -1};
	}

	auto parent_sgid = st.st_mode & S_ISGID;
	auto parent_gid = st.st_gid;

	// The new file. This is just to get gid for debug print.
	if (fstatat(at.dirfd(), at.path(), &st,
		    AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) == -1)
	{
		cerr << "ERROR: stat new file: " << strerror(errno) << endl;

		return {parent_sgid, parent_gid, -1};
	}

	return { parent_sgid, parent_gid, st.st_gid };
}

// Assumes that op returns -1 on failure
static int as_user(const fuse_path_at &at, const string &opname,
		   function<int()> op)
{
	auto c = fuse_req_ctx(at.req());

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
	if (fs.debug())
	{
		cerr << "DEBUG: " << opname << " " << at.path() <<
			" as user " << c->uid << "," << c->gid <<
			": access denied. " <<
			"fallback to do as root and chown" <<  endl;
	}

	auto opret = op();

	if (opret == -1)
		return opret;

	auto operrno = errno;

	auto gid = c->gid;
	auto [is_sgid, parent_gid, file_gid] = get_sgid_and_gids(at);

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
			if (fs.debug())
			{
				cerr << "DEBUG: file group already set to " <<
					file_gid << " due to SGID. "
					"Chown only file owner" << endl;
			}

			// To leave file group as is
			gid = -1;
		}
	}

	auto chownret = fchownat(at.dirfd(), at.path(), c->uid, gid,
			AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);

	if (chownret == -1)
		cerr << "ERROR: chown new file failed: " << strerror(errno) << endl;

	// It's important to return original op ret value, specialy for open
	errno = operrno;
	return opret;
}

static int do_mkdir(const fuse_path_at &at, mode_t mode)
{
	return as_user(at, __func__, [&](){
			return mkdirat(at.dirfd(), at.path(), mode);
		});
}

static int do_symlink(const char *link, const fuse_path_at &at)
{
	return as_user(at, __func__, [&](){
			return symlinkat(link, at.dirfd(), at.path());
		});
}

static int do_mknod(const fuse_path_at &at, mode_t mode, dev_t rdev)
{
	return as_user(at, __func__, [&](){
			return mknodat(at.dirfd(), at.path(), mode, rdev);
		});
}

static void mknod_symlink(fuse_req_t req, fuse_ino_t parent,
			  const char *name, mode_t mode, dev_t rdev,
			  const char *link)
{
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	fuse_path_at at(req, inode_p, name);
	int res;
	if (S_ISDIR(mode))
		res = call_op(mkdir)(at, mode);
	else if (S_ISLNK(mode))
		res = call_op(symlink)(link, at);
	else
		res = call_op(mknod)(at, mode, rdev);
	if (res == -1)
		goto out;

	fuse_entry_param e;
	res = call_op(lookup)(at, &e);
	if (res == -1)
		goto out;

	fuse_reply_entry(req, &e);
	return;

out:
	fuse_reply_fd_err(req, errno);
}

static void pfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode, dev_t rdev)
{
	mknod_symlink(req, parent, name, mode, rdev, nullptr);
}

static void pfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode)
{
	mknod_symlink(req, parent, name, S_IFDIR | mode, 0, nullptr);
}

static void pfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
			const char *name)
{
	mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}

static int do_link(const fuse_path_at &oldat, const fuse_path_at &newat)
{
	return linkat(oldat.dirfd(), oldat.path(), newat.dirfd(), newat.path(),
			oldat.flags(false));
}

static void pfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
		     const char *name)
{
	InodeRef inode(get_inode(ino));
	InodeRef inode_p(get_inode(parent));
	if (inode.error(req) || inode_p.error(req))
		return;

	fuse_entry_param e {};
	e.attr_timeout = fs.opts.attr_timeout;
	e.entry_timeout = fs.opts.entry_timeout;

	fuse_empty_path_at oldat(req, inode);
	fuse_path_at newat(req, inode_p, name);
	auto res = call_op(link)(oldat, newat);
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

static int do_rmdir(const fuse_path_at &at)
{
	return unlinkat(at.dirfd(), at.path(), AT_REMOVEDIR);
}

static void pfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	fuse_path_at at(req, inode_p, name);
	auto res = call_op(rmdir)(at);
	fuse_reply_errno(req, res);
}

static int do_rename(const fuse_path_at &oldat, const fuse_path_at &newat,
		     unsigned int flags)
{
	if (flags) {
		errno = EINVAL;
		return -1;
	}

	return renameat(oldat.dirfd(), oldat.path(),
			newat.dirfd(), newat.path());
}

static void forget_one(fuse_ino_t ino, uint64_t n);

static void pfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		       fuse_ino_t newparent, const char *newname,
		       unsigned int flags)
{
	InodeRef inode_p(get_inode(parent));
	InodeRef inode_np(get_inode(newparent));
	if (inode_p.error(req) || inode_np.error(req))
		return;

	fuse_path_at oldat(req, inode_p, name);
	fuse_path_at newat(req, inode_np, newname);
	auto res = call_op(rename)(oldat, newat, flags);
	if (res == -1 || !fs.at_connectable) {
		fuse_reply_errno(req, res);
		return;
	}

	// Lookup to update new parent in connectable file handle of moved inode
	fuse_entry_param e {};
	res = do_lookup(newat, &e);
	if (!res)
		forget_one(e.ino, 1);
	fuse_reply_errno(req, res);
}

static int do_unlink(const fuse_path_at &at)
{
	return unlinkat(at.dirfd(), at.path(), 0);
}

static void pfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	fuse_path_at at(req, inode_p, name);
	auto res = call_op(unlink)(at);
	fuse_reply_errno(req, res);
}

static void forget_one(fuse_ino_t ino, uint64_t n)
{
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
			lock_guard<mutex> g_fs {fs.m};
			// Mark dead inode to protect against racing with lookup
			inode.src_fh.ino = 0;
			fs.inodes.erase(ino);
			ninodes = fs.inodes.size();
		}
		if (fs.debug())
			cerr << "DEBUG: forget: cleaning up inode " << src_ino
				<< " inode count is " << ninodes << endl;
	} else if (fs.debug()) {
		cerr << "DEBUG: forget: inode " << src_ino
			<< " lookup count now " << inode.nlookup << endl;
	}
}

static void pfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	forget_one(ino, nlookup);
	fuse_reply_none(req);
}

static void pfs_forget_multi(fuse_req_t req, size_t count,
			     fuse_forget_data *forgets)
{
	for (unsigned i = 0; i < count; i++)
		forget_one(forgets[i].ino, forgets[i].nlookup);
	fuse_reply_none(req);
}

static int do_readlink(const fuse_path_at &at, char *buf, size_t size)
{
	return readlinkat(at.dirfd(), "", buf, size);
}

static void pfs_readlink(fuse_req_t req, fuse_ino_t ino)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_empty_path_at at(req, inode);
	char buf[PATH_MAX + 1];
	auto res = call_op(readlink)(at, buf, sizeof(buf));
	if (res == -1)
		fuse_reply_err(req, errno);
	else if (res == sizeof(buf))
		fuse_reply_err(req, ENAMETOOLONG);
	else {
		buf[res] = '\0';
		fuse_reply_readlink(req, buf);
	}
}


struct Dir : public fuse_file {
	DIR *dp {nullptr};
	off_t offset;

	int get_fd() override { return dirfd(dp); };
	fuse_state_t& get_state(const fuse_passthrough_module &module) {
		return module_states.get_state(module);
	}

	Dir(int num_modules) : module_states(num_modules) {}
	Dir(const Dir&) = delete;
	Dir& operator=(const Dir&) = delete;

	~Dir() {
		if(dp)
			closedir(dp);
	}

private:
	// Allow each module to store/fetch state in file
	fuse_module_states module_states;
};


static Dir *get_dir(fuse_file_info *fi)
{
	return reinterpret_cast<Dir*>(fi->fh);
}

static int do_opendir(const fuse_path_at &at, fuse_file_info *fi)
{
	auto fd = openat(at.dirfd(), at.path(), fi->flags | O_DIRECTORY);
	if (fd == -1)
		return -1;

	auto d = new (nothrow) Dir(fs.num_modules);
	if (d == nullptr) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	// On success, dir stream takes ownership of fd, so we
	// do not have to close it.
	d->dp = fdopendir(fd);
	if(d->dp == nullptr) {
		auto saverr = errno;
		delete d;
		close(fd);
		errno = saverr;
		return -1;
	}

	d->offset = 0;

	fi->fh = reinterpret_cast<uint64_t>(d);
	return 0;
}

static void pfs_opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	// Passthrough readdir by library unless module clears the flag
	// during opendir and implements the readdir operation.
	fi->passthrough_readdir = 1;

	fuse_path_at at(req, inode, ".");
	auto res = call_op(opendir)(at, fi);
	if (res == -1) {
		fuse_reply_fd_err(req, errno);
		return;
	}

	if (!fs.opts.nocache) {
		fi->keep_cache = 1;
		fi->cache_readdir = 1;
	}
	fuse_reply_open(req, fi);
	return;
}

struct fuse_readdir_at_buf {
	const fuse_path_at &at;
	char *mem;
	size_t size;
};

// Returns the number of bytes filled in buffer.
// Returns 0 if no entry written to buffer and sets errno on error.
static int fill_dir(void *_buf, const char *name, const struct stat *attr,
		    off_t off, enum fuse_fill_dir_flags flags)
{
	auto buf = (fuse_readdir_at_buf *)_buf;
	auto p = buf->mem;
	auto rem = buf->size;
	bool plus = (flags & FUSE_FILL_DIR_PLUS);

	fuse_entry_param e {};
	size_t entsize;
	// With readdirplus, lookup to get <ino,generation>
	if (plus) {
		auto err = __do_lookup(buf->at, name, &e);
		if (err) {
			errno = err;
			return 0;
		}
	} else {
		e.attr.st_ino = attr->st_ino;
		e.attr.st_mode = attr->st_mode;
	}

	if (plus)
		entsize = fuse_add_direntry_plus(NULL, p, rem, name, &e, off);
	else
		entsize = fuse_add_direntry(NULL, p, rem, name, &e.attr, off);

	if (entsize > rem) {
		if (fs.debug())
			cerr << "DEBUG: readdir(): buffer full, returning data. " << endl;
		if (e.ino)
			forget_one(e.ino, 1);
		return 0;
	}

	return entsize;
}

// Returns the number of bytes filled in buffer.
// Sets errno on error even if >0 bytes returned.
static int do_readdir(const fuse_path_at &, void *_buf, fuse_fill_dir_t filler,
		      off_t offset, struct fuse_file_info *fi,
		      enum fuse_readdir_flags flags)
{
	auto d = get_dir(fi);
	auto buf = (fuse_readdir_at_buf *)_buf;
	auto p = buf->mem;
	auto size = buf->size;
	int count = 0;
	bool plus = (flags & FUSE_READDIR_PLUS);

	if (fs.debug())
		cerr << "DEBUG: readdir(): started with offset "
			<< offset << endl;

	if (offset != d->offset) {
		if (fs.debug())
			cerr << "DEBUG: readdir(): seeking to " << offset << endl;
		seekdir(d->dp, offset);
		d->offset = offset;
	}

	while (1) {
		struct dirent *entry;
		errno = 0;
		entry = readdir(d->dp);
		if (!entry) {
			if (errno) {
				auto saverr = errno;
				if (fs.debug())
					warn("DEBUG: readdir(): readdir failed with");
				errno = saverr;
				return size - buf->size;
			}
			break; // End of stream
		}
		d->offset = entry->d_off;
		if (is_dot_or_dotdot(entry->d_name))
			continue;

		struct stat attr;
		attr.st_ino = entry->d_ino;
		attr.st_mode = entry->d_type << 12;
		auto fill_flags = plus ? FUSE_FILL_DIR_PLUS : 0;
		auto entsize = filler(_buf, entry->d_name, &attr, entry->d_off,
				      (fuse_fill_dir_flags)fill_flags);
		if (!entsize)
			break;

		p += entsize;
		buf->mem = p;
		buf->size -= entsize;
		count++;
		if (fs.debug()) {
			cerr << "DEBUG: readdir(): added to buffer: " << entry->d_name
				<< ", ino " << entry->d_ino
				<< ", offset " << entry->d_off << endl;
		}
	}

	if (fs.debug())
		cerr << "DEBUG: readdir(): returning " << count
			<< " entries, curr offset " << d->offset << endl;
	return size - buf->size;
}

static void pfs_readdir_common(fuse_req_t req, fuse_ino_t ino, size_t size,
			       off_t offset, fuse_file_info *fi,
			       enum fuse_readdir_flags flags)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	auto p = new (nothrow) char[size];
	if (!p) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	fuse_fd_path_at at(req, inode, fi);
	fuse_readdir_at_buf buf { .at = at, .mem = p, .size = size };
	// Passthrough readdir unless flag was cleared on opendir() or
	// if the module does not implements the readdir operation.
	auto res = (fi->passthrough_readdir ? do_readdir : fs.oper.readdir)
		   (at, &buf, fill_dir, offset, fi, flags);
	// If there's an error, we can only signal it if we haven't stored
	// any entries yet - otherwise we'd end up with wrong lookup
	// counts for the entries that are already in the buffer. So we
	// return what we've collected until that point.
	if (errno && res == 0) {
		fuse_reply_fd_err(req, errno);
	} else {
		fuse_reply_buf(req, p, res);
	}
	delete[] p;
	return;
}

static void pfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			off_t offset, fuse_file_info *fi)
{
	// operation logging is done in readdir to reduce code duplication
	pfs_readdir_common(req, ino, size, offset, fi, (fuse_readdir_flags)0);
}

static void pfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			    off_t offset, fuse_file_info *fi)
{
	// operation logging is done in readdir to reduce code duplication
	pfs_readdir_common(req, ino, size, offset, fi, FUSE_READDIR_PLUS);
}

static int do_releasedir(const fuse_path_at &, fuse_file_info *fi)
{
	release_file(fi);
	return 0;
}

static void pfs_releasedir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	call_op(releasedir)(at, fi);
	fuse_reply_err(req, 0);
}

static int do_release(const fuse_path_at &, fuse_file_info *fi)
{
	release_file(fi);
	return 0;
}

static int do_create(const fuse_path_at &at, mode_t mode, fuse_file_info *fi)
{
	auto fd = as_user(at, __func__, [&](){
			return openat(at.dirfd(), at.path(),
				(fi->flags | O_CREAT), mode);
		});

	if (fd == -1)
		return -1;

	auto fh = new (nothrow) File(fd, fs.num_modules);
	if (!fh) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	fi->fh = reinterpret_cast<uint64_t>(fh);
	return 0;
}

static void pfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, fuse_file_info *fi)
{
	InodeRef inode_p(get_inode(parent));
	if (inode_p.error(req))
		return;

	// Passthrough read/write by library unless module clears the flags
	// during open and implements the {read,write}_buf operations.
	fi->passthrough_read = 1;
	fi->passthrough_write = 1;

	fuse_path_at at(req, inode_p, name);
	auto res = call_op(create)(at, mode, fi);
	if (res == -1) {
		fuse_reply_fd_err(req, errno);
		return;
	}

	fuse_entry_param e;
	res = call_op(lookup)(at, &e);
	if (res == -1) {
		auto saverr = errno;
		call_op(release)(at, fi);
		fuse_reply_fd_err(req, saverr);
		return;
	}

	fi->noflush = !fs.opts.wbcache;
	fuse_reply_create(req, &e, fi);
}

static int do_open(const fuse_path_at &in, fuse_file_info *fi)
{
	// Convert empty path to magic symlink
	fuse_path_at_cwd out(in);
	auto flags = fi->flags;
	if (out.follow())
	       flags &= ~O_NOFOLLOW;
	auto fd = openat(out.dirfd(), out.path(), flags);
	if (fd == -1)
		return -1;

	auto fh = new (nothrow) File(fd, fs.num_modules);
	if (!fh) {
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	fi->fh = reinterpret_cast<uint64_t>(fh);
	return 0;
}

static void pfs_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	/* With writeback cache, kernel may send read requests even
	   when userspace opened write-only */
	if (fs.opts.wbcache && (fi->flags & O_ACCMODE) == O_WRONLY) {
		fi->flags &= ~O_ACCMODE;
		fi->flags |= O_RDWR;
	}

	/* With writeback cache, O_APPEND is handled by the kernel.  This
	   breaks atomicity (since the file may change in the underlying
	   filesystem, so that the kernel's idea of the end of the file
	   isn't accurate anymore). However, no process should modify the
	   file in the underlying filesystem once it has been read, so
	   this is not a problem. */
	if (fs.opts.wbcache && fi->flags & O_APPEND)
		fi->flags &= ~O_APPEND;

	// Passthrough read/write by library unless module clears the flags
	// during open and implements the {read,write}_buf operations.
	fi->passthrough_read = 1;
	fi->passthrough_write = 1;

	/* Unfortunately we cannot use inode.fd, because this was opened
	   with O_PATH (so it doesn't allow read/write access). */
	fuse_empty_path_at at(req, inode);
	auto res = call_op(open)(at, fi);
	if (res == -1) {
		fuse_reply_fd_err(req, errno);
		return;
	}
	fi->keep_cache = !fs.opts.nocache;
	fi->noflush = !fs.opts.wbcache;
	fuse_reply_open(req, fi);
}

static void pfs_release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	if (fs.opts.async_flush && fi->flush)
		call_op(flush)(at, fi);
	call_op(release)(at, fi);
	fuse_reply_err(req, 0);
}

static int do_flush(const fuse_path_at &, fuse_file_info *fi)
{
	return close(dup(get_file_fd(fi)));
}

static void pfs_flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	auto res = call_op(flush)(at, fi);
	fuse_reply_errno(req, res);
}

static int do_fsync(const fuse_path_at &, int datasync, fuse_file_info *fi)
{
	auto fd = get_file_fd(fi);
	if (datasync)
		return fdatasync(fd);
	else
		return fsync(fd);
}

static void pfs_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
			 fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	auto res = call_op(fsyncdir)(at, datasync, fi);
	fuse_reply_errno(req, res);
}

static void pfs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
		      fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	auto res = call_op(fsync)(at, datasync, fi);
	fuse_reply_errno(req, res);
}

static int do_read_buf(const fuse_path_at &, struct fuse_bufvec **pbuf, size_t,
		       off_t off, fuse_file_info *fi)
{
	auto buf = *pbuf;
	buf->buf[0].flags = static_cast<fuse_buf_flags>(
			FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
	buf->buf[0].fd = get_file_fd(fi);
	buf->buf[0].pos = off;
	return 0;
}

static void pfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		     fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
	auto pbuf = &buf;
	// Passthrough read unless the flag was clearen on open() or if module
	// does not implements the read_buf operation.
	auto res = (fi->passthrough_read ? do_read_buf : fs.oper.read_buf)
		   (at, &pbuf, size, off, fi);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_data(req, &buf, FUSE_BUF_COPY_FLAGS);
}

static int do_write_buf(const fuse_path_at &, struct fuse_bufvec *out_buf, off_t off,
			fuse_file_info *fi)
{
	out_buf->buf[0].flags = static_cast<fuse_buf_flags>(
			FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
	out_buf->buf[0].fd = get_file_fd(fi);
	out_buf->buf[0].pos = off;
	return 0;
}

static void pfs_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *in_buf,
			  off_t off, fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	auto size {fuse_buf_size(in_buf)};
	fuse_bufvec out_buf = FUSE_BUFVEC_INIT(size);
	// Passthrough write unless flag was cleared on open() or if module
	// does not implements the write_buf operation.
	auto res = (fi->passthrough_write ? do_write_buf : fs.oper.write_buf)
		   (at, &out_buf, off, fi);
	if (res == -1)
		fuse_reply_err(req, errno);
	res = fuse_buf_copy(&out_buf, in_buf, FUSE_BUF_COPY_FLAGS);
	if (res < 0)
		fuse_reply_err(req, -res);
	else
		fuse_reply_write(req, (size_t)res);
}

static int do_statfs(const fuse_path_at &at, struct statvfs *stbuf)
{
	return (at.dirfd() == AT_FDCWD) ?
		statvfs(at.path(), stbuf) :
		fstatvfs(at.dirfd(), stbuf);
}

static void pfs_statfs(fuse_req_t req, fuse_ino_t ino)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	struct statvfs stbuf;
	fuse_empty_path_at at(req, inode);
	auto res = call_op(statfs)(at, &stbuf);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_statfs(req, &stbuf);
}

#ifdef HAVE_FALLOCATE
static int do_fallocate(const fuse_path_at &, int mode, off_t offset,
			off_t length, fuse_file_info *fi)
{
	return fallocate(get_file_fd(fi), mode, offset, length);
}

static void pfs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
			  off_t offset, off_t length, fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	auto res = call_op(fallocate)(at, mode, offset, length, fi);
	fuse_reply_errno(req, res);
}
#endif

static int do_flock(const fuse_path_at &, fuse_file_info *fi, int op)
{
	return flock(get_file_fd(fi), op);
}

static void pfs_flock(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi,
		      int op)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	auto res = call_op(flock)(at, fi, op);
	fuse_reply_errno(req, res);
}

static off_t do_lseek(const fuse_path_at &, off_t off, int whence,
		      struct fuse_file_info *fi)
{
	return lseek(get_file_fd(fi), off, whence);
}

static void pfs_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
		      struct fuse_file_info *fi)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_fd_path_at at(req, inode, fi);
	auto res = call_op(lseek)(at, off, whence, fi);
	if (res != -1)
		fuse_reply_lseek(req, res);
	else
		fuse_reply_err(req, errno);
}

#ifdef HAVE_SETXATTR
static int do_getxattr(const fuse_path_at &in, const char *name, char *value,
		       size_t size)
{
	// Convert empty path to magic symlink
	fuse_path_at_cwd out(in);
	if (out.empty()) {
		errno = EINVAL;
		return -1;
	}
	return (out.follow() ? getxattr : lgetxattr)
		(out.path(), name, value, size);
}

static void pfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			 size_t size)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_empty_path_at at(req, inode);
	char *value = nullptr;
	ssize_t ret;
	int saverr;

	if (size) {
		value = new (nothrow) char[size];
		if (value == nullptr) {
			saverr = ENOMEM;
			goto out;
		}

		ret = call_op(getxattr)(at, name, value, size);
		if (ret == -1)
			goto out_err;
		saverr = 0;
		if (ret == 0)
			goto out;

		fuse_reply_buf(req, value, ret);
	} else {
		ret = call_op(getxattr)(at, name, nullptr, 0);
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

static int do_listxattr(const fuse_path_at &in, char *value, size_t size)
{
	// Convert empty path to magic symlink
	fuse_path_at_cwd out(in);
	if (out.empty()) {
		errno = EINVAL;
		return -1;
	}
	return (out.follow() ? listxattr : llistxattr)(out.path(), value, size);
}

static void pfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_empty_path_at at(req, inode);
	char *value = nullptr;
	ssize_t ret;
	int saverr;

	if (size) {
		value = new (nothrow) char[size];
		if (value == nullptr) {
			saverr = ENOMEM;
			goto out;
		}

		ret = call_op(listxattr)(at, value, size);
		if (ret == -1)
			goto out_err;
		saverr = 0;
		if (ret == 0)
			goto out;

		fuse_reply_buf(req, value, ret);
	} else {
		ret = call_op(listxattr)(at, nullptr, 0);
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

static int do_setxattr(const fuse_path_at &in, const char *name, const char *value,
		       size_t size, int flags)
{
	// Convert empty path to magic symlink
	fuse_path_at_cwd out(in);
	if (out.empty()) {
		errno = EINVAL;
		return -1;
	}
	return (out.follow() ? setxattr : lsetxattr)
		(out.path(), name, value, size, flags);
}

static void pfs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			 const char *value, size_t size, int flags)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_empty_path_at at(req, inode);
	auto res = call_op(setxattr)(at, name, value, size, flags);
	fuse_reply_errno(req, res);
}

static int do_removexattr(const fuse_path_at &in, const char *name)
{
	// Convert empty path to magic symlink
	fuse_path_at_cwd out(in);
	if (out.empty()) {
		// No removexattrat()
		errno = EINVAL;
		return -1;
	}
	return (out.follow() ? removexattr : lremovexattr)(out.path(), name);
}

static void pfs_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	InodeRef inode(get_inode(ino));
	if (inode.error(req))
		return;

	fuse_empty_path_at at(req, inode);
	auto res = call_op(removexattr)(at, name);
	fuse_reply_errno(req, res);
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

static ssize_t do_copy_file_range(const fuse_path_at &,
				struct fuse_file_info *fi_in, off_t off_in,
				const fuse_path_at &,
				struct fuse_file_info *fi_out, off_t off_out,
				size_t len, int flags)
{
	return copy_file_range(get_file_fd(fi_in), &off_in,
				get_file_fd(fi_out), &off_out, len, flags);
}

static void pfs_copy_file_range(fuse_req_t req, fuse_ino_t ino_in, off_t off_in,
		struct fuse_file_info *fi_in, fuse_ino_t ino_out, off_t off_out,
		struct fuse_file_info *fi_out, size_t len, int flags)
{
	InodeRef inode_in(get_inode(ino_in));
	InodeRef inode_out(get_inode(ino_out));
	if (inode_in.error(req) || inode_out.error(req))
		return;

	fuse_fd_path_at at_in(req, inode_in, fi_in);
	fuse_fd_path_at at_out(req, inode_out, fi_out);
	auto res = call_op(copy_file_range)(at_in, fi_in, off_in, at_out,
					    fi_out, off_out, len, flags);
	if (res < 0)
		fuse_reply_err(req, errno);
	else
		fuse_reply_write(req, res);
}


static void assign_default_operations(fuse_passthrough_operations &oper)
{
	oper.lookup = do_lookup;
	oper.mkdir = do_mkdir;
	oper.mknod = do_mknod;
	oper.symlink = do_symlink;
	oper.readlink = do_readlink;
	oper.link = do_link;
	oper.unlink = do_unlink;
	oper.rmdir = do_rmdir;
	oper.rename = do_rename;
	oper.getattr = do_getattr;
	oper.chmod = do_chmod;
	oper.chown = do_chown;
	oper.truncate = do_truncate;
	oper.utimens = do_utimens;
	oper.opendir = do_opendir;
	oper.readdir = do_readdir;
	oper.releasedir = do_releasedir;
	oper.fsyncdir = do_fsync;
	oper.create = do_create;
	oper.open = do_open;
	oper.release = do_release;
	oper.flush = do_flush;
	oper.fsync = do_fsync;
	oper.read_buf = do_read_buf;
	oper.write_buf = do_write_buf;
	oper.statfs = do_statfs;
#ifdef HAVE_FALLOCATE
	oper.fallocate = do_fallocate;
#endif
	oper.flock = do_flock;
	oper.lseek = do_lseek;
#ifdef HAVE_SETXATTR
	oper.setxattr = do_setxattr;
	oper.getxattr = do_getxattr;
	oper.listxattr = do_listxattr;
	oper.removexattr = do_removexattr;
#endif
	oper.copy_file_range = do_copy_file_range;
}

static void assign_lowlevel_ops(fuse_lowlevel_ops &pfs_oper)
{
	pfs_oper.init = pfs_init;
	pfs_oper.lookup = pfs_lookup;
	pfs_oper.mkdir = pfs_mkdir;
	pfs_oper.mknod = pfs_mknod;
	pfs_oper.symlink = pfs_symlink;
	pfs_oper.link = pfs_link;
	pfs_oper.unlink = pfs_unlink;
	pfs_oper.rmdir = pfs_rmdir;
	pfs_oper.rename = pfs_rename;
	pfs_oper.forget = pfs_forget;
	pfs_oper.forget_multi = pfs_forget_multi;
	pfs_oper.getattr = pfs_getattr;
	pfs_oper.setattr = pfs_setattr;
	pfs_oper.readlink = pfs_readlink;
	pfs_oper.opendir = pfs_opendir;
	pfs_oper.readdir = pfs_readdir;
	pfs_oper.readdirplus = pfs_readdirplus;
	pfs_oper.releasedir = pfs_releasedir;
	pfs_oper.fsyncdir = pfs_fsyncdir;
	pfs_oper.create = pfs_create;
	pfs_oper.open = pfs_open;
	pfs_oper.release = pfs_release;
	if (fs.opts.async_flush)
		pfs_oper.flush = pfs_flush;
	pfs_oper.fsync = pfs_fsync;
	pfs_oper.read = pfs_read;
	pfs_oper.write_buf = pfs_write_buf;
	pfs_oper.statfs = pfs_statfs;
#ifdef HAVE_FALLOCATE
	pfs_oper.fallocate = pfs_fallocate;
#endif
	pfs_oper.flock = pfs_flock;
	pfs_oper.lseek = pfs_lseek;
#ifdef HAVE_SETXATTR
	pfs_oper.setxattr = pfs_setxattr;
	pfs_oper.getxattr = pfs_getxattr;
	pfs_oper.listxattr = pfs_listxattr;
	pfs_oper.removexattr = pfs_removexattr;
#endif
	pfs_oper.copy_file_range = pfs_copy_file_range;
}

static void assign_operations(fuse_passthrough_operations &oper,
			      const fuse_passthrough_operations &in,
			      const fuse_passthrough_operations &def)
{
	oper.lookup = in.lookup ?: def.lookup;
	oper.mkdir = in.mkdir ?: def.mkdir;
	oper.mknod = in.mknod ?: def.mknod;
	oper.symlink = in.symlink ?: def.symlink;
	oper.readlink = in.readlink ?: def.readlink;
	oper.link = in.link ?: def.link;
	oper.unlink = in.unlink ?: def.unlink;
	oper.rmdir = in.rmdir ?: def.rmdir;
	oper.rename = in.rename ?: def.rename;
	oper.getattr = in.getattr ?: def.getattr;
	oper.chmod = in.chmod ?: def.chmod;
	oper.chown = in.chown ?: def.chown;
	oper.truncate = in.truncate ?: def.truncate;
	oper.utimens = in.utimens ?: def.utimens;
	oper.opendir = in.opendir ?: def.opendir;
	oper.readdir = in.readdir ?: def.readdir;
	oper.releasedir = in.releasedir ?: def.releasedir;
	oper.fsyncdir = in.fsyncdir ?: def.fsync;
	oper.create = in.create ?: def.create;
	oper.open = in.open ?: def.open;
	oper.release = in.release ?: def.release;
	oper.flush = in.flush ?: def.flush;
	oper.fsync = in.fsync ?: def.fsync;
	oper.read_buf = in.read_buf ?: def.read_buf;
	oper.write_buf = in.write_buf ?: def.write_buf;
	oper.statfs = in.statfs ?: def.statfs;
	oper.fallocate = in.fallocate ?: def.fallocate;
	oper.flock = in.flock ?: def.flock;
	oper.lseek = in.lseek ?: def.lseek;
	oper.setxattr = in.setxattr ?: def.setxattr;
	oper.getxattr = in.getxattr ?: def.getxattr;
	oper.listxattr = in.listxattr ?: def.listxattr;
	oper.removexattr = in.removexattr ?: def.removexattr;
	oper.copy_file_range = in.copy_file_range ?: def.copy_file_range;
}

static void assign_module_operations(fuse_passthrough_module &module,
				     fuse_passthrough_module &head)
{
	// Initialize module next operations to either the operations of the
	// head module or the head module's next operations
	assign_operations(module.next, head.oper, head.next);
	// Initialize fs next operations to either operations of the new
	// module or leave the current fs next operations
	assign_operations(fs.next, module.oper, fs.next);
	module.idx = head.idx + 1;
}

static void maximize_fd_limit()
{
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


int fuse_passthrough_main(fuse_args *args, fuse_passthrough_opts &opts,
			  fuse_passthrough_module *modules[], int num_modules,
			  size_t oper_size)
{
	struct fuse_loop_config *loop_config = NULL;

	// We may need an fd for every dentry in our the filesystem that the
	// kernel knows about. This is way more than most processes need,
	// so try to get rid of any resource softlimit.
	maximize_fd_limit();

	// Initialize filesystem root
	fs.num_modules = num_modules;
	fs.opts = opts;
	fs.init_root();

	if (oper_size != sizeof(fs.oper))
		errx(1, "ERROR: incompatible library ABI");

	// Assign default operations to default fs
	assign_default_operations(fs.oper);
	assign_default_operations(fs.next);
	// Chain module operations terminating with default fs operations
	fuse_passthrough_module *head = &fs;
	while (num_modules-- > 0) {
		assign_module_operations(**modules, *head);
		head = *modules;
		modules++;
	}

	// Initialize fuse
	auto ret = -1;
	fuse_lowlevel_ops pfs_oper {};
	assign_lowlevel_ops(pfs_oper);
	auto se = fuse_session_new(args, &pfs_oper, sizeof(pfs_oper), &fs);
	if (se == nullptr)
		goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;

	// Mount and run main loop
	loop_config = fuse_loop_cfg_create();

	fuse_loop_cfg_set_clone_fd(loop_config, opts.clone_fd);
	if (opts.max_threads)
		fuse_loop_cfg_set_max_threads(loop_config, opts.max_threads);
	if (opts.max_idle_threads)
		fuse_loop_cfg_set_idle_threads(loop_config, opts.max_idle_threads);

	if (fuse_session_mount(se, opts.mountpoint.c_str()) != 0)
		goto err_out3;

	fuse_daemonize(opts.foreground);

	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else
		ret = fuse_session_loop_mt(se, loop_config);

	fuse_session_unmount(se);

err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	fuse_loop_cfg_destroy(loop_config);
	fuse_opt_free_args(args);

	return ret ? 1 : 0;
}

