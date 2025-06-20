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
#include <filesystem>
#include <list>
#include <mutex>
#include <fstream>
#include <iostream>
#include <thread>
#include <iomanip>
#include <atomic>
#include <set>
#include <unordered_map>

#include "fuse_passthrough.h"
#include "fuse_helpers.h"
#include "notifyfs.h"
#include "statx.h"

using namespace std;
namespace fs = std::filesystem;


class Index;

struct NotifyFs : public fuse_passthrough_module {
	bool index_all{false};
	bool index_by_src_ino{true};

	NotifyFs() : fuse_passthrough_module("notifyfs") {}

	bool set_index_path(const string &index_path);

	shared_ptr<Index> index() {
		return atomic_load(&_index);
	}

private:
	mutex _index_lock;
	shared_ptr<Index> _index;
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
	// Index state flags are w.r.t a specific index ID
	_IDX_PARENT,	// All ancestors are indexed
	_IDX_SELF,	// Directory inode itself is indexed
	_IDX_MOVED,	// Directory was moved
	// Index ID stored in upper 32bits
	_IDX_ID = 32,
};

#define IDX_INIT	(0UL)
#define IDX_PARENT	(1UL << _IDX_PARENT)
#define IDX_SELF	(1UL << _IDX_SELF)
#define IDX_MOVED	(1UL << _IDX_MOVED)
#define IDX_PATH	(IDX_PARENT | IDX_SELF)
#define IDX_MASK	(IDX_PATH  | IDX_MOVED)

// True if all bits in the mask are set
#define IDX_TEST(bits, mask) \
	(((bits) & (mask)) == (mask))
#define IDX_FLAGS(bits) \
	((unsigned)((bits) & IDX_MASK))
#define IDX_ID(bits) \
	((unsigned)((bits) >> _IDX_ID))
#define IDX_BITS(id, flags) \
	((uint64_t)(flags) | (uint64_t)(id) << _IDX_ID)
#define IDX_VALID(id, bits) \
	(((bits) & ~IDX_MASK) == IDX_BITS(id, 0))

// Index state determines if inode is recorded in change tracking snapshot.
// We only ever set bits in a state after allocating a fuse_state_t.
class IndexState {
public:
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
		reset(0);
		reset(1);
	}

	void reset(unsigned id) {
		bits(id).store(IDX_INIT, memory_order_relaxed);
	}
	void set(unsigned id, unsigned flags) {
		uint64_t new_bits = IDX_BITS(id, flags);
		auto& b = bits(id);
		uint64_t expected = b.load(memory_order_relaxed);
		uint64_t desired;

		// Auto-invalidate flags referring to old id
		do {
			uint64_t old_id = IDX_ID(expected);

			if (old_id && old_id != id) {
				// Old state flags are referring to old index,
				// clear existing flags and set new ones
				desired = new_bits;
			} else {
				// Set new state flags without clearing existing flags
				desired = expected | new_bits;
			}
		} while (!b.compare_exchange_weak(expected, desired,
						  memory_order_relaxed));
	}
	bool test(unsigned id, unsigned mask) {
		auto v = bits(id).load(memory_order_relaxed);
		return IDX_VALID(id, v) && IDX_TEST(IDX_FLAGS(v), mask);
	}
	unsigned get(unsigned id) {
		auto v = bits(id).load(memory_order_relaxed);
		return IDX_VALID(id, v) ? IDX_FLAGS(v) : IDX_INIT;
	}
	atomic<uint64_t>& bits(unsigned id) {
		return _indexed[id & 1];
	}

private:
	// State bits for odd and even index ids that may exist at the same time.
	// We work under the assumption that two threads can be referencing two
	// subsequent index ids (odd and even) concurrently, but by the time of
	// the next index change, the old index will not be referenced anymore.
	atomic<uint64_t> _indexed[2] {
		ATOMIC_VAR_INIT(IDX_INIT),
		ATOMIC_VAR_INIT(IDX_INIT)
	};
};

#define IDX_STATE(s) (reinterpret_cast<IndexState *>(s))

enum index_op {
	OP_RO,
	OP_RW,
	OP_MOVE,
	OP_PARENT,
};

struct fill_index_ctx {
	Index *index;
	ino_t pino;
	index_op op;
};


class Index {
public:
	Index() {}
	Index(const string &path, chrono::nanoseconds btime, unsigned id, int dirfd) :
		_index_dir_path(path), _index_dir_btime(btime), _index_id(id),
		_dirfd(dirfd) {}
	~Index() {
		if (_dirfd >= 0)
			close(_dirfd);
	}

	bool dir_is_new(int dirfd, const char *path = "") const;
	string fid_index_path(const file_handle &fid) const;
	bool check_index_moved(const string &index_path, bool &created);
	void inode_check_index(const fuse_inode &inode, IndexState *idx,
			       fill_index_ctx *ctx);
	IndexState *get_index_state(ino_t ino, index_op op, ino_t pino = 0);
	bool index_parents(IndexState *idx);

	bool is_valid() const {
		return !_index_dir_path.empty();
	}
	bool btime_supported() const {
		return _index_dir_btime != 0ns;
	}
	string dir_path() const {
		return _index_dir_path;
	}
	unsigned id() const {
		return _index_id;
	}

private:
	string _index_dir_path;
	chrono::nanoseconds _index_dir_btime{0ns};
	unsigned _index_id{0};
	int _dirfd{-1};
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

string Index::fid_index_path(const file_handle &fid) const
{
	return buf2hex(fid.f_handle, fid.handle_bytes);
}

// Get immutable creation time of directory from filesystem (e.g. xfs, ext4)
static pair<chrono::nanoseconds, ino_t> get_dir_btime_ino(int dirfd, const char *path)
{
	chrono::nanoseconds nsec{0ns};
	struct statx stx = {};

	if (statx(dirfd, path, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH,
		  STATX_MODE | STATX_BTIME, &stx)) {
		if (nfyfs.debug())
			cerr << "ERROR: statx() failed" << endl;
		return {nsec, 0};
	}

	if (S_ISDIR(stx.stx_mode) && (stx.stx_mask & STATX_BTIME)) {
		// Pre 1970 btime not supported
		if (stx.stx_btime.tv_sec < 0)
			return {nsec, 0};

		nsec = chrono::seconds{stx.stx_btime.tv_sec} +
			chrono::nanoseconds{stx.stx_btime.tv_nsec};
	}

	return {nsec, stx.stx_ino};
}

// Check if directory was created after index dir
bool Index::dir_is_new(int dirfd, const char *path) const
{
	if (!btime_supported())
		return false;

	auto [btime, ino] = get_dir_btime_ino(dirfd, path);
	if (btime <= _index_dir_btime)
		return false;

	if (nfyfs.debug())
		cerr << "DEBUG: directory inode " << ino
			<< " is newer than index" << endl;

	return true;
}

// The opaque xattr is meaningless on overlayfs index entries.
// We use it as an arbitrary mark of a moved directory
#define OVL_XATTR_OPAQUE "trusted.overlay.opaque"

// Check if inode was marked as moved
bool Index::check_index_moved(const string &fid_path, bool &created)
{
	auto index_path = _index_dir_path + '/' + fid_path;
	auto res = lgetxattr(index_path.c_str(), OVL_XATTR_OPAQUE, NULL, 0);
	if (res > 0)
		return true;

	if (lsetxattr(index_path.c_str(), OVL_XATTR_OPAQUE, "y", 1, 0))
		return false;

	created = true;
	return true;
}

// Check if index was marked as modified
static bool check_index_modified(const struct stat &st)
{
	// atime > mtime means no modification since last check
	if (st.st_atime > st.st_mtime)
		return false;

	// mtime > atime means modified since last check
	if (st.st_mtime > st.st_atime)
		return true;

	// mkdir and touch set mtime = atime, so atime == mtime is modified
	return st.st_mtim.tv_nsec >= st.st_atim.tv_nsec;
}

void Index::inode_check_index(const fuse_inode &inode, IndexState *idx,
			      fill_index_ctx *ctx)
{
	auto const isdir = inode.is_dir();
	// Create index if does not exist for all parent dirs before change
	// Update index entry timestamp for the direct parent only before change
	auto const create = isdir && (ctx->op != OP_RO);
	auto const update = create && (ctx->op != OP_PARENT);
	auto const move = (ctx->op == OP_MOVE);

	// We treat root as "parent indexed" and root itself
	// will be indxed on the first modification
	if (inode.is_root())
		idx->set(id(), IDX_PARENT);

	if (move && !update && idx->test(id(), IDX_MOVED))
		return;

	if (!move && !update && idx->test(id(), IDX_SELF))
		return;

	// We index directories by FUSE nodeid, so we can get state of parent
	// in all the operations.  If FUSE ino is the same as source ino, we can
	// also get state of subdir when we have it's source ino for indexing
	// moved directories.  Otherwise, we need to disable directory move.
	if (move && nfyfs.index_by_src_ino && inode.nodeid() != inode.ino()) {
		nfyfs.index_by_src_ino = false;
		if (nfyfs.debug())
			cerr << "DEBUG: disabled directory move" << endl;
	}

	// Treat all non-dir and new directories as indexed and moved,
	// becauses we only need to trigger indexing for directories that
	// existed at the time that index was created.
	if (!isdir || dir_is_new(inode.get_fd())) {
		idx->set(id(), IDX_SELF | IDX_MOVED);
		return;
	}

	auto fid_path = fid_index_path(idx->fid.fh);
	struct stat stat;
	auto ret = fstatat(_dirfd, fid_path.c_str(), &stat, AT_SYMLINK_NOFOLLOW);
	auto created = false;
	auto updated = false;
	if (ret == -1) {
		if (errno != ENOENT || !create)
			return;

		ret = mkdirat(_dirfd, fid_path.c_str(), 0755);
		created = (ret == 0);
		if (ret == -1 && errno != EEXIST)
			return;
	} else if (update && !check_index_modified(stat)) {
		// Update index timestamp if it was already observed (atime > mtime)
		ret = utimensat(_dirfd, fid_path.c_str(), NULL, AT_SYMLINK_NOFOLLOW);
		updated = (ret == 0);
	} else if (!move && idx->test(id(), IDX_SELF)) {
		// Reduce debug noise - if index was not created/updated and dir
		// was already cached as indexed, do not print debug message
		return;
	}

	if (move && !idx->test(id(), IDX_MOVED) && check_index_moved(fid_path, created))
		idx->set(id(), IDX_MOVED);

	if (nfyfs.debug())
		cerr << "DEBUG: directory inode " << inode.ino()
			<< (created ? " was now" :
			   (updated ? " once again" : " is already"))
			<< (move ? " marked moved" : " indexed") << endl;

	idx->set(id(), IDX_SELF);
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

	ctx->index->inode_check_index(inode, idx, ctx);

	return init;
}

//
// Get inode index state
//
// @pino 0 means get existing inode state with any idx->parent.
// Otherwise, find or create a state with @pino as idx->parent.
IndexState *Index::get_index_state(ino_t ino, index_op op, ino_t pino)
{
	fill_index_ctx ctx = {
		.index = this,
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

#define MAX_PATH_DEPTH 100

bool Index::index_parents(IndexState *idx)
{
	auto pidx = idx;
	auto parent = idx->parent;

	// Walk back the chain of idx->parent states, indexing the
	// ancestors, until hitting an ancestor with indexed path
	unordered_map<ino_t, IndexState *> ancestors;
	while (parent) {
		if (pidx->test(id(), IDX_PATH))
			break;

		// Test for loops and too deep path
		if (ancestors.size() >= MAX_PATH_DEPTH ||
		    ancestors.find(parent) != ancestors.end()) {
			cerr << "ERROR: illegal ancestors path " << idx->parent
				<< "...(" << ancestors.size()
				<< ")..." << parent << endl;
			return false;
		}

		pidx = get_index_state(parent, OP_PARENT);
		if (!pidx || pidx->parent == parent || !pidx->test(id(), IDX_SELF)) {
			pidx = NULL;
			break;
		}

		// All ancestors up to root are indexed
		if (parent == FUSE_ROOT_ID)
			break;

		ancestors[parent] = pidx;
		parent = pidx->parent;
	}

	if (!parent || !pidx) {
		cerr << "ERROR: disconnected ancestors path " << idx->parent
			<< "...(" << ancestors.size()
			<< ")..." << parent << endl;
		return false;
	}

	// Mark all ancestors indexed path
	for (auto& [ino, pidx] : ancestors)
		pidx->set(id(), IDX_PARENT);

	return true;
}

// Check if dir and parents are indexed in change tracking snapshot
static bool __index_path_at(Index *index, const fuse_path_at &at, index_op op,
			    const char *caller)
{
	if (!index || !index->is_valid())
		return true;

	auto &inode = at.inode();
	auto ino = inode.nodeid();
	ino_t pino = 0;
	auto move = (op == OP_MOVE);

	if (move) {
		struct stat st;
		if (fstatat(at.dirfd(), at.path(), &st, at.flags()))
			return false;

		// Even if we cannot indexed moved directory, we can allow
		// move of directories newer than index
		if (!S_ISDIR(st.st_mode) ||
		    index->dir_is_new(at.dirfd(), at.path()))
			return true;

		// We need to check the index of a moved directory
		// and we can only do that if inodes are indexed by
		// source st_ino
		if (!nfyfs.index_by_src_ino)
			return false;

		// Index the moved subdir
		pino = ino;
		ino = st.st_ino;
	}

	auto idx = index->get_index_state(ino, op, pino);
	if (!idx)
		return false;

	auto rw = (op != OP_RO);
	auto id = index->id();
	if (rw && !idx->test(id, IDX_PARENT) && index->index_parents(idx))
		idx->set(id, IDX_PARENT);

	if (nfyfs.debug()) {
		cerr << "DEBUG: " << caller << "(" << at.path() << ")"
			<< " inode " << ino << " index " << id
			<< " state 0x" << hex << noshowbase
			<< idx->get(id) << dec << endl;
	}

	// Do not allow move of directory unless it is marked as moved in index
	if (move && !idx->test(id, IDX_MOVED))
		return false;

	// Do not allow modifications to inode unless all path elements
	// (all parent directories and self) are indexed or newer than index.
	return !rw || idx->test(id, IDX_PATH);
}

#define index_ro_path_at(index, at) index_path_at(index, at, OP_RO, EPERM)
#define index_rw_path_at(index, at) index_path_at(index, at, OP_RW, EPERM)
#define index_move_path_at(index, at) index_path_at(index, at, OP_MOVE, EXDEV)
#define index_path_at(index, at, op, err)			\
	if (!__index_path_at((index).get(), (at), (op), __func__)) {	\
		errno = (err);				\
		return -1;				\
	}

//
// notifyfs operations
//
static int nfyfs_lookup(const fuse_path_at &at, fuse_entry_param *e)
{
	auto index = nfyfs.index();
	index_ro_path_at(index, at);
	auto ret = next_op(lookup)(at, e);
	if (ret)
		return ret;

	if (!index || !index->is_valid())
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
	auto pidx = index->get_index_state(pino, OP_RO);
	if (!pidx) {
		cerr << "ERROR: no parent index state. ino=" << pino << endl;
		// If we fail lookup now, we would need to call forget() API...
		return 0;
	}

	auto id = index->id();
	auto parent_indexed = pidx->test(id, IDX_PATH);
	if (nfyfs.debug()) {
		cerr << "DEBUG: parent " << pino << " indexed " << id
			<< " state 0x" << hex << noshowbase
			<< pidx->get(id) << dec << endl;
	}

	// Inode state is created on lookup() and may be updated later
	// Lookup of same inode from a different path (e.g. hardlink)
	// will reset the inode state to that of the new path.
	auto idx = index->get_index_state(e->ino, OP_RO, pino);
	if (!idx) {
		cerr << "ERROR: no index state. ino=" << e->ino << endl;
		// If we fail lookup now, we would need to call forget() API...
		return 0;
	}

	// Record in inode state if all its ancestors are indexed
	if (parent_indexed) {
		idx->set(id, IDX_PARENT);
	} else if (idx->test(id, IDX_PARENT)) {
		// This can happen if ancestor was renamed in the source
		// from an indexed path without indexing the new path
		idx->reset(id);
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
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(chmod)(at, mode, fi);
}

static int nfyfs_chown(const fuse_path_at &at, uid_t uid, gid_t gid,
		       fuse_file_info *fi)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(chown)(at, uid, gid, fi);
}

static int nfyfs_truncate(const fuse_path_at &at, off_t size, fuse_file_info *fi)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(truncate)(at, size, fi);
}

static int nfyfs_utimens(const fuse_path_at &at, const struct timespec tv[2],
			 struct fuse_file_info *fi)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(utimens)(at, tv, fi);
}

static int nfyfs_mkdir(const fuse_path_at &at, mode_t mode)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(mkdir)(at, mode);
}

static int nfyfs_symlink(const char *link, const fuse_path_at &at)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(symlink)(link, at);
}

static int nfyfs_mknod(const fuse_path_at &at, mode_t mode, dev_t rdev)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(mknod)(at, mode, rdev);
}

static int nfyfs_link(const fuse_path_at &oldat, const fuse_path_at &newat)
{
	auto index = nfyfs.index();
	index_ro_path_at(index, oldat);
	index_rw_path_at(index, newat);
	return next_op(link)(oldat, newat);
}

static int nfyfs_rmdir(const fuse_path_at &at)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(rmdir)(at);
}

static int nfyfs_rename(const fuse_path_at &oldat, const fuse_path_at &newat,
			unsigned int flags)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, oldat);
	index_rw_path_at(index, newat);
	// Mark directory moved or return EXDEV error
	// to let userspace fall back to recursive move
	index_move_path_at(index, oldat);
	return next_op(rename)(oldat, newat, flags);
}

static int nfyfs_unlink(const fuse_path_at &at)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(unlink)(at);
}

static int nfyfs_create(const fuse_path_at &at, mode_t mode, fuse_file_info *fi)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(create)(at, mode, fi);
}

static int nfyfs_open(const fuse_path_at &at, fuse_file_info *fi)
{
	index_op op = ((fi->flags & O_ACCMODE) == O_RDONLY) ? OP_RO : OP_RW;
	auto index = nfyfs.index();
	index_path_at(index, at, op, EPERM);
	return next_op(open)(at, fi);
}

static int nfyfs_setxattr(const fuse_path_at &at, const char *name,
			  const char *value, size_t size, int flags)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
	return next_op(setxattr)(at, name, value, size, flags);
}

static int nfyfs_removexattr(const fuse_path_at &at, const char *name)
{
	auto index = nfyfs.index();
	index_rw_path_at(index, at);
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

bool NotifyFs::set_index_path(const string &index_path)
{
	lock_guard<mutex> lock(_index_lock);
	error_code ec;
	auto canonical_path = fs::canonical(index_path, ec);
	if (ec) {
		cerr << "ERROR: canonical(" << index_path << ") failed: "
			<< ec.message() << endl;
		return false;
	}

	// Nothing to do when setting to same index path
	auto path = canonical_path.string();
	auto old_index = index();
	if (old_index && old_index->dir_path() == path)
		return true;

	auto dirfd = openat(AT_FDCWD, path.c_str(),
			    O_PATH | O_DIRECTORY | O_NOFOLLOW);
	if (dirfd < 0) {
		cerr << "open(" << path << ") failed: "
			<< strerror(errno) << endl;
		return false;
	}

	auto [btime, ino] = get_dir_btime_ino(dirfd, "");
	if (index_all)
		btime = 0ns;

	unsigned id = old_index ? old_index->id() : 0;
	if (++id == 0) {
		// Do not allow wraparound of index id
		cerr << "ERROR: index id wraparound." << endl;
		close(dirfd);
		return false;
	}

	try {
		auto index = make_shared<Index>(path, btime, id, dirfd);
		cout << "INFO: Created index " << id << " on " << path << endl;
		atomic_store(&_index, index);
	} catch (const std::bad_alloc& e) {
		cerr << "ERROR: Allocate new index failed: " << e.what() << endl;
		close(dirfd);
		return false;
	}
	return true;
}

void nfyfs_init(fuse_passthrough_opts &opts, const string &index_path, bool index_all)
{
	nfyfs.opts = opts;
	nfyfs_assign_operations(nfyfs.oper);
	nfyfs.index_all = index_all;
	nfyfs.set_index_path(index_path);
	auto index = nfyfs.index();
	if (!index || !index->is_valid()) {
		cerr << "ERROR: invalid index dir " << index_path << endl;
	} else if (index->btime_supported()) {
		cout << "INFO: creation time not supported by filesystem on "
			<< index_path << endl;
	} else if (index_all) {
		cout << "INFO: ignoring index creation time" << endl;
	}
}

fuse_passthrough_module *nfyfs_module(void)
{
	return &nfyfs;
}
