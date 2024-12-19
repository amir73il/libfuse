/*
  notifyfs: FUSE passthrough module

  Copyright (C) 2021-2024  CTERA Networks

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * Notifyfs tracks changes to files and records them in an overlayfs
 * indexed snapshot.
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
#include <fuse.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>


// C++ includes
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <list>
#include <mutex>
#include <fstream>
#include <iostream>
#include <thread>
#include <iomanip>
#include <atomic>
#include <set>

#include "fuse_passthrough.h"
#include "fuse_helpers.h"
#include "notifyfs.h"
#include "statx.h"

using namespace std;


struct NotifyFs : public fuse_passthrough_module {
	string index_prefix;
	chrono::nanoseconds index_btime{0ns};

	NotifyFs() : fuse_passthrough_module("notifyfs") {}

	// Filesystem is indexed by fhandles using a change tracking snapshot
	// index_prefix is not a directory, it's a template of a directory entry name.
	bool is_indexed() {
		return !index_prefix.empty();
	}
	bool btime_supported() {
		return index_btime != 0ns;
	}
};
static NotifyFs nfyfs{};

#define next_op(op) call_module_next_op(nfyfs, op)


// Indexed state bits
enum {
	_IDX_PARENT,	// All ancestors are indexed
	_IDX_SELF,	// Directory inode itself is indexed
};

#define IDX_INIT	0U
#define IDX_PARENT	(1U << _IDX_PARENT)
#define IDX_SELF	(1U << _IDX_SELF)
#define IDX_PATH	(IDX_PARENT | IDX_SELF)
#define IDX_MASK	(IDX_PATH)

// True if all bits in the mask are set
#define IDX_TEST(bits, mask) \
	(((bits) & (mask)) == (mask))
#define IDX_VALID(bits) \
	(!((bits) & ~IDX_MASK))

// Index state determines if inode is recorded in change tracking snapshot.
// We only ever set bits in a state after allocating a fuse_state_t.
// Resetting an index state is only possible via clear_module_inode_state().
struct IndexState {
	IndexState() = default;

	bool set(unsigned mask) {
		return IDX_VALID(indexed.fetch_or(mask, memory_order_relaxed));
	}
	bool test(unsigned mask) {
		return IDX_TEST(indexed.load(memory_order_relaxed), mask);
	}
	unsigned bits() {
		return indexed.load(memory_order_relaxed);
	}

private:
	atomic<unsigned> indexed {ATOMIC_VAR_INIT(IDX_INIT)};
};

#define IDX_STATE(s) ((IndexState *) (s).get())

enum index_op {
	OP_RO,
	OP_RW,
	OP_MOVE,
};

struct fill_index_ctx {
	bool create;
	index_op op;
};


static string buf2hex(const unsigned char *buf, unsigned int size)
{
	char          hex_str[]= "0123456789abcdef";
	unsigned int  i;

	if (!size)
		return "";

	char result[256];
	result[size * 2] = 0;

	for (i = 0; i < size; i++)
	{
		result[i * 2 + 0] = hex_str[buf[i] >> 4  ];
		result[i * 2 + 1] = hex_str[buf[i] & 0x0F];
	}

	result[size*2+1] = '\0';

	return result;
}

static string fh_index_path(struct file_handle *fh)
{
	return nfyfs.index_prefix + buf2hex(fh->f_handle, fh->handle_bytes);
}

// Get immutable creation time of directory from filesystem (e.g. xfs, ext4)
static chrono::nanoseconds get_dir_btime_nsec(int dirfd, const char *path)
{
	chrono::nanoseconds nsec{0ns};
	struct statx stx = {};

	if (statx(dirfd, path, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH,
		  STATX_MODE | STATX_BTIME, &stx)) {
		if (nfyfs.debug())
			cerr << "ERROR: statx() failed" << endl;
		return nsec;
	}

	if (S_ISDIR(stx.stx_mode) && (stx.stx_mask & STATX_BTIME)) {
		// Pre 1970 btime not supported
		if (stx.stx_btime.tv_sec < 0)
			return nsec;

		nsec = chrono::seconds{stx.stx_btime.tv_sec} +
			chrono::nanoseconds{stx.stx_btime.tv_nsec};
	}

	return nsec;
}

// Check if directory was created after index dir
static bool dir_is_new(int dirfd, ino_t ino)
{
	if (!nfyfs.btime_supported())
		return false;

	auto btime = get_dir_btime_nsec(dirfd, "");
	if (btime <= nfyfs.index_btime)
		return false;

	if (nfyfs.debug())
		cerr << "DEBUG: directory inode " << ino
			<< " is newer than index" << endl;

	return true;
}

static void inode_check_index(const fuse_inode &inode, IndexState *idx,
			      fill_index_ctx *ctx)
{
	if (idx->test(IDX_SELF))
		return;

	// Treat all non-dir and new directories as indexed, becauses we
	// only need to trigger indexing for directories that existed
	// at the time that index was created.
	if (!inode.is_dir() || dir_is_new(inode.get_fd(), inode.ino())) {
		idx->set(IDX_SELF);
		return;
	}

	auto index_path = fh_index_path(inode.get_file_handle());
	struct stat stat;
	auto ret = lstat(index_path.c_str(), &stat);
	auto rw = (ctx->op != OP_RO);
	if (ret == -1) {
		if (errno != ENOENT || !rw)
			return;

		ret = mkdir(index_path.c_str(), 0755);
		if (ret == -1 && errno != EEXIST)
			return;
	} else {
		rw = false;
	}

	if (nfyfs.debug())
		cerr << "DEBUG: directory inode " << inode.ino()
			<< (rw ? " was now" : " is already")
			<< " indexed" << endl;

	idx->set(IDX_SELF);
	return;
}

static bool fill_index_state(const fuse_inode &inode,
			     fuse_state_t &state, void *data)
{
	auto idx = IDX_STATE(state);
	auto ctx = (fill_index_ctx *) data;

	if (!idx) {
		if (!ctx->create)
			return false;

		idx = new (nothrow) IndexState;
		if (!idx) {
			if (nfyfs.debug())
				cerr << "ERROR: failed allocating indexed state"
					<< " ino=" << inode.ino() << endl;
			return false;
		}

		state.reset(idx);
	}

	inode_check_index(inode, idx, ctx);

	return true;
}

static IndexState *get_index_state(ino_t ino, fuse_state_t &state,
				   index_op op, bool create = false)
{
	fill_index_ctx ctx = {
		.create = create,
		.op = op,
	};

	if (!get_module_inode_state(nfyfs, ino, state, fill_index_state,
				    (void *)&ctx))
		return NULL;

	return IDX_STATE(state);
}

// Check if dir and parents are indexed in change tracking snapshot
static bool __index_path_at(const fuse_path_at &at, index_op op,
			    const char *caller)
{
	if (!nfyfs.is_indexed())
		return true;

	auto &inode = at.inode();
	// Treat root as indexed
	if (inode.is_root())
		return true;

	fuse_state_t state;
	auto idx = get_index_state(inode.nodeid(), state, op);
	if (!idx)
		return false;

	if (nfyfs.debug())
		cerr << "DEBUG: " << caller << "(" << at.path() << ")"
			<< " inode " << inode.ino()
			<< " index state " << idx->bits() << endl;

	// Do not allow modifications to inode unless all path elements
	// (all parent directories and self) are indexed or newer than index.
	return (op == OP_RO) || idx->test(IDX_PATH);
}

#define index_ro_path_at(at) index_path_at(at, OP_RO, EPERM)
#define index_rw_path_at(at) index_path_at(at, OP_RW, EPERM)
#define index_path_at(at, op, err)			\
	if (!__index_path_at((at), (op), __func__)) {	\
		errno = (err);				\
		return -1;				\
	}

//
// notifyfs operations
//
static int nfyfs_lookup(const fuse_path_at &at, fuse_entry_param *e)
{
	index_ro_path_at(at);
	auto ret = next_op(lookup)(at, e);
	if (ret)
		return ret;

	if (!nfyfs.is_indexed())
		return 0;

	auto &parent = at.inode();
	fuse_state_t& parent_state = parent.get_state(nfyfs);
	IndexState *idx;
	auto parent_indexed = parent.is_root();
	if (parent_indexed)
		goto init_state;

	if (is_dot_or_dotdot(at.path()) || !parent_state) {
		// If we fail lookup now, we need to call forget() API...
		return 0;
	}

	idx = IDX_STATE(parent_state);
	parent_indexed = idx->test(IDX_PATH);
	if (nfyfs.debug())
		cerr << "DEBUG: parent " << parent.ino()
			<< " indexed state " << idx->bits() << endl;

init_state:
	// Inode state is created on lookup() and may be updated later
	fuse_state_t state;
	idx = get_index_state(e->ino, state, OP_RO, true);
	if (!idx) {
		cerr << "ERROR: no index state. ino=" << e->ino << endl;
		return 0;
	}

	// Record in inode state if all its ancestors are indexed
	if (parent_indexed)
		idx->set(IDX_PARENT);

	return 0;
}

static int nfyfs_chmod(const fuse_path_at &at, mode_t mode, fuse_file_info *fi)
{
	index_rw_path_at(at);
	return next_op(chmod)(at, mode, fi);
}

static int nfyfs_chown(const fuse_path_at &at, uid_t uid, gid_t gid,
		       fuse_file_info *fi)
{
	index_rw_path_at(at);
	return next_op(chown)(at, uid, gid, fi);
}

static int nfyfs_truncate(const fuse_path_at &at, off_t size, fuse_file_info *fi)
{
	index_rw_path_at(at);
	return next_op(truncate)(at, size, fi);
}

static int nfyfs_utimens(const fuse_path_at &at, const struct timespec tv[2],
			 struct fuse_file_info *fi)
{
	index_rw_path_at(at);
	return next_op(utimens)(at, tv, fi);
}

static int nfyfs_mkdir(const fuse_path_at &at, mode_t mode)
{
	index_rw_path_at(at);
	return next_op(mkdir)(at, mode);
}

static int nfyfs_symlink(const char *link, const fuse_path_at &at)
{
	index_rw_path_at(at);
	return next_op(symlink)(link, at);
}

static int nfyfs_mknod(const fuse_path_at &at, mode_t mode, dev_t rdev)
{
	index_rw_path_at(at);
	return next_op(mknod)(at, mode, rdev);
}

static int nfyfs_link(const fuse_path_at &oldat, const fuse_path_at &newat)
{
	index_ro_path_at(oldat);
	index_rw_path_at(newat);
	return next_op(link)(oldat, newat);
}

static int nfyfs_rmdir(const fuse_path_at &at)
{
	index_rw_path_at(at);
	return next_op(rmdir)(at);
}

static int nfyfs_rename(const fuse_path_at &oldat, const fuse_path_at &newat,
			unsigned int flags)
{
	index_rw_path_at(oldat);
	index_rw_path_at(newat);
	return next_op(rename)(oldat, newat, flags);
}

static int nfyfs_unlink(const fuse_path_at &at)
{
	index_rw_path_at(at);
	return next_op(unlink)(at);
}

static int nfyfs_create(const fuse_path_at &at, mode_t mode, fuse_file_info *fi)
{
	index_rw_path_at(at);
	return next_op(create)(at, mode, fi);
}

static int nfyfs_open(const fuse_path_at &at, fuse_file_info *fi)
{
	index_op op = ((fi->flags & O_ACCMODE) == O_RDONLY) ? OP_RO : OP_RW;
	index_path_at(at, op, EPERM);
	return next_op(open)(at, fi);
}

static int nfyfs_setxattr(const fuse_path_at &at, const char *name,
			  const char *value, size_t size, int flags)
{
	index_rw_path_at(at);
	return next_op(setxattr)(at, name, value, size, flags);
}

static int nfyfs_removexattr(const fuse_path_at &at, const char *name)
{
	index_rw_path_at(at);
	return next_op(removexattr)(at, name);
}


static void nfyfs_assign_operations(fuse_passthrough_operations &oper)
{
	oper.lookup = nfyfs_lookup;
	oper.chmod = nfyfs_chmod;
	oper.chown = nfyfs_chown;
	oper.truncate = nfyfs_truncate;
	oper.utimens = nfyfs_utimens;
	oper.mkdir = nfyfs_mkdir;
	oper.mknod = nfyfs_mknod;
	oper.symlink = nfyfs_symlink;
	oper.link = nfyfs_link;
	oper.rmdir = nfyfs_rmdir;
	oper.rename = nfyfs_rename;
	oper.unlink = nfyfs_unlink;
	oper.create = nfyfs_create;
	oper.open = nfyfs_open;
	oper.setxattr = nfyfs_setxattr;
	oper.removexattr = nfyfs_removexattr;
}

void nfyfs_init(fuse_passthrough_opts &opts, string index_path)
{
	nfyfs.opts = opts;
	nfyfs_assign_operations(nfyfs.oper);
	nfyfs.index_prefix = index_path + '/';
	nfyfs.index_btime = get_dir_btime_nsec(AT_FDCWD, index_path.c_str());
	if (!nfyfs.btime_supported()) {
		cerr << "INFO: creation time not supported by filesystem on "
			<< index_path << endl;
	}
}

fuse_passthrough_module *nfyfs_module(void)
{
	return &nfyfs;
}
