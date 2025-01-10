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

#define FID64_SIZE 12

struct fid64 {
	bool is_valid() const {
		return fh.handle_type && fh.handle_bytes &&
			fh.handle_bytes <= FID64_SIZE;
	}
	bool operator!=(const fid64 &fid) const {
		return !is_valid() ||
			fh.handle_bytes != fid.fh.handle_bytes ||
			memcmp(buf, fid.buf, fh.handle_bytes);
	}

	struct file_handle fh;
	unsigned char buf[FID64_SIZE];
};

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
struct IndexState {
	fid64 fid;
	ino_t parent;

	IndexState(const file_handle &fh, ino_t pino) { reset(fh, pino); }
	void reset(const file_handle &fh, ino_t pino) {
		parent = pino;
		fid.fh = fh;
		if (fid.is_valid())
			memcpy(fid.buf, fh.f_handle, fh.handle_bytes);
		else
			fid.fh.handle_bytes = 0;
		set(IDX_INIT);
	}

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

#define IDX_STATE(s) (reinterpret_cast<IndexState *>(s))

enum index_op {
	OP_RO,
	OP_RW,
	OP_MOVE,
};

struct fill_index_ctx {
	ino_t pino;
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

static string fid_index_path(const file_handle &fid)
{
	return nfyfs.index_prefix + buf2hex(fid.f_handle, fid.handle_bytes);
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

	auto index_path = fid_index_path(idx->fid.fh);
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
	auto ino = inode.ino();
	auto pino = ctx->pino;
	auto init = false;
	fid64 fid = {};

	fid.fh.handle_bytes = FID64_SIZE;
	if (!inode.get_fid(fid.fh) || !fid.is_valid()) {
		cerr << "ERROR: failed to get valid fid"
			<< " ino=" << ino
			<< " fh_len=" << fid.fh.handle_bytes << endl;
		return false;
	}

	if (!idx) {
		// Lazy init root inode index state on first access
		if (!pino && !inode.is_root()) {
			if (nfyfs.debug())
				cerr << "ERROR: no indexed state"
					<< " ino=" << ino << endl;
			return false;
		}

		idx = new (nothrow) IndexState(fid.fh, pino);
		if (!idx) {
			cerr << "ERROR: failed allocating indexed state"
				<< " parent=" << pino
				<< " ino=" << ino << endl;
			return false;
		}

		// We treat root as "parent indexed" and root itself
		// will be indxed on the first modification
		if (inode.is_root())
			idx->set(IDX_PARENT);

		if (nfyfs.debug())
			cerr << "DEBUG: fill_state=0x" << hex << idx
				<< ", ino=" << dec << ino << endl;

		state = reinterpret_cast<fuse_state_t>(idx);
		init = true;
	} else {
		auto reset = false;

		// Reset existing state on idx->fid mismatch
		if (fid != idx->fid) {
			reset = true;
			if (nfyfs.debug())
				cerr << "DEBUG: reset inode " << ino << " fid" << endl;
		}
		// Reset existing state on idx->parent mismatch
		if (pino && pino != idx->parent) {
			reset = true;
			if (nfyfs.debug())
				cerr << "DEBUG: reset inode " << ino
					<< " indexed state "
					<< " old parent " << idx->parent
					<< " new parent " << pino << endl;
		}

		if (reset)
			idx->reset(fid.fh, pino);
	}

	inode_check_index(inode, idx, ctx);

	return init;
}

//
// Get inode index state
//
// @pino 0 means get existing inode state with any idx->parent.
// Otherwise, find or create a state with @pino as idx->parent.
static IndexState *get_index_state(ino_t ino, index_op op, ino_t pino = 0)
{
	fill_index_ctx ctx = {
		.pino = pino,
		.op = op,
	};

	fuse_state_t state;
	if (!get_module_inode_state(nfyfs, ino, state, fill_index_state,
				    (void *)&ctx)) {
		if (nfyfs.debug())
			cerr << "DEBUG: inode " << ino
				<< " has no state" << endl;
		return NULL;
	}

	auto idx = IDX_STATE(state);
	if (nfyfs.debug())
		cerr << "DEBUG: get_state=0x" << hex << idx
			<< ", ino=" << dec << ino << endl;

	return idx;
}

// Check if dir and parents are indexed in change tracking snapshot
static bool __index_path_at(const fuse_path_at &at, index_op op,
			    const char *caller)
{
	if (!nfyfs.is_indexed())
		return true;

	auto &inode = at.inode();
	auto ino = inode.nodeid();
	auto idx = get_index_state(ino, op);
	if (!idx)
		return false;

	if (nfyfs.debug())
		cerr << "DEBUG: " << caller << "(" << at.path() << ")"
			<< " inode " << ino
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

	// Only initialize state on forward path+name lookup.
	// If notifyfs is exported to nfs it should be exported with
	// subtree_check option, so that every operation on a file open
	// by handle will first need to find the file by forward lookup
	// and properly initialize its index state.
	// Trying to operate on a file opened by handle without subtree_check
	// may lead to EPERM if the file's inode was not previously indexed.
	if (is_dot_or_dotdot(at.path()))
		return 0;

	auto &parent = at.inode();
	auto pino = parent.nodeid();
	auto pidx = get_index_state(pino, OP_RO);
	if (!pidx) {
		cerr << "ERROR: no parent index state. ino=" << pino << endl;
		// If we fail lookup now, we would need to call forget() API...
		return 0;
	}

	auto parent_indexed = pidx->test(IDX_PATH);
	if (nfyfs.debug())
		cerr << "DEBUG: parent " << pino
			<< " indexed state " << pidx->bits() << endl;

	// Inode state is created on lookup() and may be updated later
	// Lookup of same inode from a different path (e.g. hardlink)
	// will reset the inode state to that of the new path.
	auto idx = get_index_state(e->ino, OP_RO, pino);
	if (!idx) {
		cerr << "ERROR: no index state. ino=" << e->ino << endl;
		// If we fail lookup now, we would need to call forget() API...
		return 0;
	}

	// Record in inode state if all its ancestors are indexed
	if (parent_indexed) {
		idx->set(IDX_PARENT);
	} else if (idx->test(IDX_PARENT)) {
		// This can happen if ancestor was renamed in the source
		// from an indexed path without indexing the new path
		idx->set(IDX_INIT);
		if (nfyfs.debug())
			cerr << "ERROR: resetting inconsistent indexed state"
				<< " parent=" << pino
				<< " ino=" << e->ino << endl;
	}

	return 0;
}

static int nfyfs_forget(const fuse_path_at &at)
{
	auto &inode = at.inode();
	auto ret = inode.get_state(nfyfs);
	if (!ret)
		return 0;

	auto idx = IDX_STATE(ret.value());
	if (nfyfs.debug())
		cerr << "DEBUG: forget_state=0x" << hex << idx
			<< ", ino=" << dec << inode.ino() << endl;

	inode.set_state(nfyfs, 0);
	// delete index state before deleting inode
	delete idx;
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
	oper.forget = nfyfs_forget;
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

void nfyfs_init(fuse_passthrough_opts &opts, string index_path, bool index_all)
{
	nfyfs.opts = opts;
	nfyfs_assign_operations(nfyfs.oper);
	nfyfs.index_prefix = index_path + '/';
	nfyfs.index_btime = get_dir_btime_nsec(AT_FDCWD, index_path.c_str());
	if (!nfyfs.btime_supported()) {
		cout << "INFO: creation time not supported by filesystem on "
			<< index_path << endl;
	} else if (index_all) {
		nfyfs.index_btime = 0ns;
		cout << "INFO: ignoring index creation time" << endl;
	}
}

fuse_passthrough_module *nfyfs_module(void)
{
	return &nfyfs;
}
