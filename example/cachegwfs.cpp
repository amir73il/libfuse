/*
  cachegwfs: FUSE passthrough module

  Copyright (C) 2021-2024  CTERA Networks

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * cachegwfs mirrors a specified "source" directory under a
 * specified the mountpoint and "redirects" operations on
 * "stub" files and directories to another "redirect" path.
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
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>


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

#include "fuse_passthrough.h"
#include "fuse_helpers.h"

using namespace std;


enum op {
	OP_REDIRECT, // Force redirect
	OP_LOOKUP,
	OP_GETATTR,
	OP_OPEN_RO,
	OP_OPEN_RW,
	OP_OPENDIR,
	OP_STATFS,
	OP_CHMOD,
	OP_CHOWN,
	OP_TRUNCATE,
	OP_UTIMENS,
	// "writedir" operations on parent directory
	OP_CREATE,
	OP_MKDIR,
	OP_MVDIR,
	OP_RMDIR,
	OP_MKNOD,
	OP_LINK,
	OP_RENAME,
	OP_UNLINK,
	OP_SYMLINK,
	// redirect for specific xattr name prefixes
	OP_GETXATTR,
	OP_SETXATTR,
	// redirect fd opened in open() and used in copy_file_range() if needed
	OP_COPY,
	// redirect all ops with --redirect cmdline option
	OP_ALL,
};

const map<enum op, const char *> op_names = {
	{ OP_LOOKUP, "lookup" },
	{ OP_GETATTR, "getattr" },
	{ OP_OPEN_RO, "open_ro" },
	{ OP_OPEN_RW, "open_rw" },
	{ OP_OPENDIR, "opendir" },
	{ OP_STATFS, "statfs" },
	{ OP_CHMOD, "chmod" },
	{ OP_CHOWN, "chown" },
	{ OP_TRUNCATE, "truncate" },
	{ OP_UTIMENS, "utimens" },
	{ OP_CREATE, "create" },
	{ OP_MKDIR, "mkdir" },
	{ OP_MVDIR, "mvdir" },
	{ OP_RMDIR, "rmdir" },
	{ OP_MKNOD, "mknod" },
	{ OP_LINK, "link" },
	{ OP_RENAME, "rename" },
	{ OP_UNLINK, "unlink" },
	{ OP_SYMLINK, "symlink" },
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
	vector<string> read_xattr;
	vector<string> write_xattr;
	vector<string> readdir_xattr;
	vector<string> writedir_xattr;
	vector<string> xattr_prefixes;
	unordered_set<enum op> ops; // fs operations to redirect
	unordered_set<uint64_t> folder_ids; // folder ids to redirect

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

static Redirect *read_config_file();

struct CgwFs : public fuse_passthrough_module {
	string redirect_path;
	string config_file;

	CgwFs() : fuse_passthrough_module("cachegwfs") {
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

private:
	atomic_flag config_is_valid {ATOMIC_FLAG_INIT};
	shared_ptr<Redirect> _redirect;
};
static CgwFs fs{};

#define next_op(op) call_module_next_op(fs, op)


// Check if the operation @op was configured with redirect_op rule
// or if this file/directory is an empty place holder (a.k.a stub)
// Return true if any of the above conditions are met.
static bool should_redirect_fd(int fd, const char *procname, enum op op)
{
	// redirect all ops with --redirect cmdline option
	if (fs.redirect_op(OP_ALL))
		return true;

	// redirect specific op with config redirect_op = <op name>
	if (fs.redirect_op(op))
		return true;

	bool rw = false, is_dir = false;
	switch (op) {
	case OP_LOOKUP:
	case OP_OPENDIR:
		is_dir = true;
		break;
	case OP_OPEN_RO:
		break;
	case OP_CREATE:
		// before create() we are called with dirfd+name and file does not
		// exist, so we check stub xattr on parent dir.
		// after create() we are called again with the opened file fd and
		// then we need to verify that the opened file is not a stub.
		is_dir = !!procname;
		// fallthrough
	case OP_OPEN_RW:
		rw = true;
		break;
	case OP_MKNOD:
	case OP_MKDIR:
	case OP_RMDIR:
	case OP_MVDIR:
	case OP_LINK:
	case OP_UNLINK:
	case OP_RENAME:
	case OP_SYMLINK:
		rw = true;
		is_dir = true;
		break;
	default:
		return fs.redirect_op(op);
	}

	// redirect read/write if it has stub xattr
	auto r = fs.redirect();
	const auto &redirect_xattr = rw ?
		(is_dir ? r->writedir_xattr : r->write_xattr) :
		(is_dir ? r->readdir_xattr : r->read_xattr);

	for (const auto& xattr : redirect_xattr) {
		ssize_t res;

		if (procname)
			res = getxattr(procname, xattr.c_str(), NULL, 0);
		else
			res = fgetxattr(fd, xattr.c_str(), NULL, 0);
		if (res > 0)
			return true;
	}
	return false;
}

// Convert <dirfd+name> to redirected path if @op is in redirect ops
// and on open of a stub file or directory
static fuse_path_at get_fd_path_op(const fuse_path_at &in, enum op op)
{
	__trace_fd_path_at(in, op_name(op));

	auto dirfd = in.dirfd();
	auto name = in.path();

	if (dirfd == AT_FDCWD) {
		// No dirfd - return a copy of the path we got
		return in;
	}

	int n = 0;
	char linkname[PATH_MAX];
	bool redirect = should_redirect_fd(dirfd, in.proc_path(), op);
	if (redirect)
		n = readlink(in.proc_path(), linkname, PATH_MAX);

	int prefix = fs.opts.source.size();
	if (redirect && prefix && n >= prefix &&
	    !memcmp(fs.opts.source.c_str(), linkname, prefix)) {
		linkname[n] = 0;
		auto outpath = fs.redirect_path;
		if (fs.redirect_path.empty())
			outpath.append(linkname);
		else
			outpath.append(linkname + prefix, n - prefix);
		if (!in.empty()) {
			outpath.append("/");
			outpath.append(name);
		}
		if (fs.debug())
			cerr << "DEBUG: redirect " << op_name(op)
				<< " |=> " << outpath << endl;
		// Return redirected path
		return fuse_path_at_cwd(in, outpath.c_str());
	} else {
		if (redirect && prefix) {
			// We need to redirect, but we don't know where to
			cerr << "ERROR: redirect " << op_name(op) << "(" << name << "): "
				<< linkname << " not under " << fs.opts.source << endl;
		}
		// Return a copy of the path we got
		return in;
	}
}

static uint64_t *get_folder_id(const fuse_state_t &state)
{
	return (uint64_t *)state.get();
}

static bool should_redirect_folder_id(const fuse_path_at &at)
{
	auto r = fs.redirect();
	fuse_state_t& state = at.inode().get_state(fs);

	if (state && r->test_folder_id(*get_folder_id(state)))
		return true;

	return false;
}

static enum op redirect_open_op(const fuse_path_at &at, fuse_file_info *fi)
{
	enum op op;

	if (fi->flags & O_CREAT)
		op = OP_CREATE;
	else if ((fi->flags & O_ACCMODE) == O_RDONLY)
		return OP_OPEN_RO;
	else
		op = OP_OPEN_RW;

	if (should_redirect_folder_id(at))
		return OP_REDIRECT;

	return op;
}

struct File {
	int get_fd() const { return _fd; };

	File() = delete;
	File(const File&) = delete;
	File& operator=(const File&) = delete;

	File(int fd) : _fd(fd) {
		if (fs.debug())
			cerr << "DEBUG: open(): redirect_fd=" << _fd << endl;
	}
	~File() {
		if (fs.debug())
			cerr << "DEBUG: close(): redirect_fd=" << _fd << endl;
		if (_fd > 0)
			close(_fd);
	}

private:
	int _fd {-1};
};

static int get_file_redirect_fd(fuse_file_info *fi)
{
	fuse_state_t& state = get_file_state(fi, fs);

	if (!state)
		return -1;

	auto rfd = reinterpret_cast<File *>(state.get())->get_fd();
	// AT_FDCWD state means open itself was redirected
	return rfd == AT_FDCWD ? get_file_fd(fi) : rfd;
}

static bool set_file_redirect_fd(fuse_file_info *fi, int rfd)
{
	fuse_state_t& state = get_file_state(fi, fs);

	if (state)
		return false;

	auto p = new (nothrow) File(rfd);
	if (!p) {
		if (fs.debug())
			cerr << "ERROR: Allocate file state failed."
				<< endl;
		return false;
	}

	state.reset(p);
	return true;
}

static int open_redirect_fd(const fuse_path_at &in, int flags)
{
	auto out = get_fd_path_op(in, OP_REDIRECT);

	if (!out.follow())
		flags &= ~O_NOFOLLOW;

	return open(out.path(), flags);
}

static int check_safe_fd(fuse_file_info *fi, enum op op)
{
	auto fd = get_file_fd(fi);

	// cachegw manager takes an exclusive lock before making file a stub
	if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
		auto saverr = errno;
		cerr << "INFO: file is locked for read/write access." << endl;
		errno = saverr;
		return -1;
	}

	// Check that file is still not a stub after lock
	if (!should_redirect_fd(fd, NULL, op))
		return 0;

	cerr << "INFO: file open raced with evict." << endl;
	errno = EAGAIN;
	return -1;
}

static int finish_open(const fuse_path_at &at, fuse_file_info *fi, enum op op)
{
	auto redirected = (at.dirfd() == AT_FDCWD && !at.follow());
	int rfd = 0;
	bool fail = false;

	if (redirected) {
		// Store AT_FDCWD state to indicate that open was redirected
		rfd = AT_FDCWD;
	} else if (check_safe_fd(fi, op) == -1) {
		fail = true;
	} else if (fs.redirect_op(OP_COPY)) {
		// open redirect fd in addition to the bypass fd.
		// when called from create(), we must not try to create
		// a file in redirect path, only to open it.
		rfd = open_redirect_fd(at, fi->flags & ~O_CREAT);
		if (rfd == -1)
			fail = true;
	}

	if (!fail && rfd && !set_file_redirect_fd(fi, rfd))
		fail = true;

	if (fail) {
		release_file(fi);
		return -1;
	}

	return 0;
}

static bool path_is_dir(const fuse_path_at &at)
{
	struct stat st;

	if (fstatat(at.dirfd(), at.path(), &st, at.flags()) == 0)
		return S_ISDIR(st.st_mode);

	return false;
}

//
// cachegwfs operations
//
static int cgwfs_lookup(const fuse_path_at &at, fuse_entry_param *e)
{
	// Check if reading parent directory should be redirected
        // and lookup child in redirected path to trigger populate of the
	// stub directory before lookup in source path
	if (!is_dot_or_dotdot(at.path())) {
		auto out = get_fd_path_op(at, OP_LOOKUP);
		if (out.dirfd() != at.dirfd() &&
		    faccessat(out.dirfd(), out.path(), F_OK, out.flags())) {
			if (fs.debug())
				cerr << "faccessat(" << out.path() << ", " << out.flags()
					<< "): " << strerror(errno) << endl;
			return -1;
		}
	}
	// Lookup itself is never in the redirected path, because we
	// need to find the real xfs inode
	auto ret = next_op(lookup)(at, e);
	if (ret)
		return ret;

	// If subdir name is not a decimal number, the folder id is undefined.
	// For all other inodes, it is inheritted from the parent.
	fuse_state_t state;
	fuse_state_t& parent_state = at.inode().get_state(fs);
	if (at.inode().is_root() && S_ISDIR(e->attr.st_mode)) {
		uint64_t folder_id = strtoull(at.path(), NULL, 10);
		if (fs.debug() && folder_id)
			cerr << "DEBUG: first level subdir folder id "
				<< folder_id << endl;

		if (folder_id) {
			auto p = new (nothrow) uint64_t;
			if (p) {
				*p = folder_id;
				state.reset(p);
			} else if (fs.debug()) {
				cerr << "ERROR: Allocate inode state failed."
					<< endl;
			}
		}
	} else if (parent_state) {
		state = parent_state;
		if (fs.debug())
			cerr << "DEBUG: inherit parent folder id "
				<< *get_folder_id(state) << endl;
	}

	if (state && !set_module_inode_state(fs, e->ino, state)) {
		if (fs.debug())
			cerr << "ERROR: failed setting folder id "
				<< *get_folder_id(state)
				<< " ino=" << e->ino << endl;
	}

	return 0;
}

static int cgwfs_getattr(const fuse_path_at &in, struct stat *attr,
			 fuse_file_info *fi)
{
	auto out = get_fd_path_op(in, OP_GETATTR);
	return next_op(getattr)(out, attr, fi);
}

static int cgwfs_chmod(const fuse_path_at &in, mode_t mode, fuse_file_info *fi)
{
	auto out = get_fd_path_op(in, OP_CHMOD);
	return next_op(chmod)(out, mode, fi);
}

static int cgwfs_chown(const fuse_path_at &in, uid_t uid, gid_t gid,
		       fuse_file_info *fi)
{
	auto out = get_fd_path_op(in, OP_CHOWN);
	return next_op(chown)(out, uid, gid, fi);
}

static int cgwfs_truncate(const fuse_path_at &in, off_t size, fuse_file_info *fi)
{
	auto out = get_fd_path_op(in, OP_TRUNCATE);
	return next_op(truncate)(out, size, fi);
}

static int cgwfs_utimens(const fuse_path_at &in, const struct timespec tv[2],
			 struct fuse_file_info *fi)
{
	auto out = get_fd_path_op(in, OP_UTIMENS);
	return next_op(utimens)(out, tv, fi);
}

static int cgwfs_mkdir(const fuse_path_at &in, mode_t mode)
{
	auto out = get_fd_path_op(in, OP_MKDIR);
	return next_op(mkdir)(out, mode);
}

static int cgwfs_symlink(const char *link, const fuse_path_at &in)
{
	auto out = get_fd_path_op(in, OP_SYMLINK);
	return next_op(symlink)(link, out);
}

static int cgwfs_mknod(const fuse_path_at &in, mode_t mode, dev_t rdev)
{
	auto out = get_fd_path_op(in, OP_MKNOD);
	return next_op(mknod)(out, mode, rdev);
}

static int cgwfs_link(const fuse_path_at &oldin, const fuse_path_at &newin)
{
	auto oldout = get_fd_path_op(oldin, OP_LINK);
	auto newout = get_fd_path_op(newin, OP_LINK);
	return next_op(link)(oldout, newout);
}

static int cgwfs_rmdir(const fuse_path_at &in)
{
	auto out = get_fd_path_op(in, OP_RMDIR);
	return next_op(rmdir)(out);
}

static enum op redirect_rename_op(const fuse_path_at &at)
{
	return path_is_dir(at) ? OP_MVDIR : OP_RENAME;
}

static int cgwfs_rename(const fuse_path_at &oldin, const fuse_path_at &newin,
			unsigned int flags)
{
	auto op = redirect_rename_op(oldin);
	auto oldout = get_fd_path_op(oldin, op);
	auto newout = get_fd_path_op(newin, op);
	return next_op(rename)(oldout, newout, flags);
}

static int cgwfs_unlink(const fuse_path_at &in)
{
	auto out = get_fd_path_op(in, OP_UNLINK);
	return next_op(unlink)(out);
}

static int cgwfs_opendir(const fuse_path_at &in, fuse_file_info *fi)
{
	auto out = get_fd_path_op(in, OP_OPENDIR);
	// Do not passthrough to redirected fd
	if (out.cwd())
		fi->passthrough_readdir = false;

	return next_op(opendir)(out, fi);
}

static int cgwfs_create(const fuse_path_at &in, mode_t mode, fuse_file_info *fi)
{
	enum op op = redirect_open_op(in, fi);
	auto out = get_fd_path_op(in, op);
	// Do not passthrough to redirected fd
	if (out.cwd())
		fi->passthrough_read = fi->passthrough_write = false;

	auto ret = next_op(create)(out, mode, fi);
	if (ret)
		return ret;

	return finish_open(out, fi, op);
}

static int cgwfs_open(const fuse_path_at &in, fuse_file_info *fi)
{
	enum op op = redirect_open_op(in, fi);
	auto out = get_fd_path_op(in, op);
	// Do not passthrough to redirected fd
	if (out.cwd())
		fi->passthrough_read = fi->passthrough_write = false;

	auto ret = next_op(open)(out, fi);
	if (ret)
		return ret;

	return finish_open(out, fi, op);
}

static int cgwfs_statfs(const fuse_path_at &in, struct statvfs *stbuf)
{
	auto out = get_fd_path_op(in, OP_STATFS);
	return next_op(statfs)(out, stbuf);
}

const string sys_acl_xattr_prefix = "system.posix_acl";

static bool xattr_starts_with(const char *name, const string &prefix)
{
	return !prefix.empty() &&
		strncmp(name, prefix.c_str(), prefix.size()) == 0;
}
static enum op redirect_xattr_op(enum op op, const char *name)
{
	if (fs.debug())
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

static int cgwfs_getxattr(const fuse_path_at &in, const char *name, char *value,
			  size_t size)
{
	auto op = redirect_xattr_op(OP_GETXATTR, name);
	auto out = get_fd_path_op(in, op);
	return next_op(getxattr)(out, name, value, size);
}

static int cgwfs_listxattr(const fuse_path_at &in, char *value, size_t size)
{
	auto out = get_fd_path_op(in, OP_GETXATTR);
	return next_op(listxattr)(out, value, size);
}

static int cgwfs_setxattr(const fuse_path_at &in, const char *name,
			  const char *value, size_t size, int flags)
{
	auto op = redirect_xattr_op(OP_SETXATTR, name);
	auto out = get_fd_path_op(in, op);
	return next_op(setxattr)(out, name, value, size, flags);
}

static int cgwfs_removexattr(const fuse_path_at &in, const char *name)
{
	auto op = redirect_xattr_op(OP_SETXATTR, name);
	auto out = get_fd_path_op(in, op);
	return next_op(removexattr)(out, name);
}

#ifndef HAVE_COPY_FILE_RANGE
static loff_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
			      loff_t *off_out, size_t len, unsigned int flags)
{
	return syscall(__NR_copy_file_range, fd_in, off_in, fd_out,
			off_out, len, flags);
}
#endif

static ssize_t cgwfs_copy_file_range(const fuse_path_at &,
				struct fuse_file_info *fi_in, off_t off_in,
				const fuse_path_at &,
				struct fuse_file_info *fi_out, off_t off_out,
				size_t len, int flags)
{
	ssize_t res;
	auto fd_in = get_file_fd(fi_in);
	auto fd_out = get_file_fd(fi_out);
	auto rfd_in = get_file_redirect_fd(fi_in);
	auto rfd_out = get_file_redirect_fd(fi_out);

	// If one of the fds are redirected, use both redirected fds for copy
	auto redirect = (fd_in == rfd_in || fd_out == rfd_out);
	if (redirect) {
		if (rfd_in == -1 || rfd_out == -1)
			return -1;

		fd_in = rfd_in;
		fd_out = rfd_out;
	}

	// To simplify, always terminate the copy_file_range() operation
	// chain without calling next module
	res = copy_file_range(fd_in, &off_in, fd_out, &off_out, len, flags);

	return res;
}


static void cgwfs_assign_operations(fuse_passthrough_operations &oper)
{
	oper.lookup = cgwfs_lookup;
	oper.getattr = cgwfs_getattr;
	oper.chmod = cgwfs_chmod;
	oper.chown = cgwfs_chown;
	oper.truncate = cgwfs_truncate;
	oper.utimens = cgwfs_utimens;
	oper.mkdir = cgwfs_mkdir;
	oper.mknod = cgwfs_mknod;
	oper.symlink = cgwfs_symlink;
	oper.link = cgwfs_link;
	oper.rmdir = cgwfs_rmdir;
	oper.rename = cgwfs_rename;
	oper.unlink = cgwfs_unlink;
	oper.opendir = cgwfs_opendir;
	oper.create = cgwfs_create;
	oper.open = cgwfs_open;
	oper.statfs = cgwfs_statfs;
	oper.setxattr = cgwfs_setxattr;
	oper.getxattr = cgwfs_getxattr;
	oper.listxattr = cgwfs_listxattr;
	oper.removexattr = cgwfs_removexattr;
	oper.copy_file_range = cgwfs_copy_file_range;
}

static void print_usage(cxxopts::Options& parser, char *prog_name) {
	cout << "\nUsage: " << prog_name << " [options] <source> <mountpoint>\n";
	// Strip everything before the option list from the
	// default help string.
	auto help = parser.help({"", "fuse"});
	cout << endl << " options:"
		<< help.substr(help.find("\n\n") + 1, string::npos) << endl;
}

static cxxopts::ParseResult parse_wrapper(cxxopts::Options& parser,
		int& argc, char**& argv)
{
	try {
		return parser.parse(argc, argv);
	} catch (cxxopts::option_not_exists_exception& exc) {
		cout << argv[0] << ": " << exc.what() << endl;
		print_usage(parser, argv[0]);
		exit(2);
	}
}


#define CONFIG_FILE "/etc/cachegwfs.conf"

static cxxopts::ParseResult parse_options(int &argc, char **argv)
{
	cxxopts::Options opt_parser(argv[0]);
	opt_parser.allow_unrecognised_options();
	opt_parser.add_options()
		("debug", "Enable filesystem debug messages")
		("help", "Print help")
		("redirect", "Redirect all operations")
		("redirect_path", "Path to access tiered files",
		 cxxopts::value<string>(), "PATH")
		("config_file", "Config file reloaded on SIGHUP",
		 cxxopts::value<string>()->default_value(CONFIG_FILE), "FILE");

	opt_parser.add_options("fuse")
		("debug-fuse", "Enable libfuse debug messages")
		("foreground", "Run in foreground")
		("nocache", "Disable all caching")
		("wbcache", "Enable writeback cache")
		("nosplice", "Do not use splice(2) to transfer data")
		("nokeepfd", "Do not keep open fd for all inodes in cache")
		("nopassthrough", "Do not use pass-through mode in kernel for read/write")
		("readdirpassthrough", "Use pass-through mode in kernel for readdir")
		("max_threads", "Max number of libfuse worker threads", cxxopts::value<int>(), "N")
		("max_idle_threads", "Max number of idle libfuse worker threads", cxxopts::value<int>(), "N")
		("single", "Run single-threaded");

	// FIXME: Find a better way to limit the try clause to just
	// opt_parser.parse() (cf. https://github.com/jarro2783/cxxopts/issues/146)
	auto options = parse_wrapper(opt_parser, argc, argv);

	if (options.count("help")) {
		print_usage(opt_parser, argv[0]);
		exit(0);

	} else if (argc < 3) {
		cout << argv[0] << ": invalid number of arguments\n";
		print_usage(opt_parser, argv[0]);
		exit(2);
	}

	fs.opts.foreground = options.count("foreground");
	fs.opts.singlethread = options.count("single");
	fs.opts.nosplice = options.count("nosplice");
	fs.opts.nocache = options.count("nocache");
	fs.opts.attr_timeout = fs.opts.nocache ? 0 : 1.0;
	fs.opts.entry_timeout = fs.opts.attr_timeout;
	fs.opts.wbcache = !fs.opts.nocache && options.count("wbcache");
	fs.opts.connected_fd = !fs.opts.keep_fd;
	fs.opts.keep_fd = !options.count("nokeepfd");
	fs.opts.connected_fd = true;
	fs.opts.kernel_passthrough = !options.count("nopassthrough");
	fs.opts.readdir_passthrough = options.count("readdirpassthrough");

	if (options.count("max_threads"))
		fs.opts.max_threads = options["max_threads"].as<int>();
	if (options.count("max_idle_threads"))
		fs.opts.max_idle_threads = options["max_idle_threads"].as<int>();

	auto rp = realpath(argv[1], NULL);
	if (!rp)
		err(1, "ERROR: realpath(\"%s\")", argv[1]);
	cout << "source is " << rp << endl;
	fs.opts.source = rp;

	auto mp = realpath(argv[2], NULL);
	if (!mp) {
		cerr << "realpath(" << argv[2] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "mount point is " << mp << endl;
	fs.opts.mountpoint = mp;

	if (options.count("redirect_path")) {
		auto path = options["redirect_path"].as<string>();
		rp = realpath(path.c_str(), NULL);
		if (!rp)
			err(1, "ERROR: realpath(\"%s\")", path.c_str());
		cout << "redirect path is " << rp << endl;
		fs.redirect_path = rp;
	}

	fs.config_file = options["config_file"].as<string>();
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
	static const regex rgx(R"(\s*([^\s=]+)\s*=\s*([^\s#]+).*)");
	smatch matches;
	regex_match(line, matches, rgx);

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

	ifstream cFile(fs.config_file);
	if (!cFile.is_open()) {
		if (fs.config_file != CONFIG_FILE)
			cerr << "ERROR: Failed to open config file "
				<< fs.config_file << endl;
		return nullptr;
	}

	Redirect *redirect = new (nothrow) Redirect();
	if (!redirect) {
		cerr << "ERROR: Allocate new config failed." << endl;
		return nullptr;
	}

	bool debug = false;
	string line;
	while (getline(cFile, line)) {
		string name, value;

		if (!parseConfigLine(line, name, value))
			continue;

		cout << name << " = " << value << endl;
		if (name == "debug") {
			debug = stoi(value);
		} else if (name == "attr_timeout") {
			fs.opts.attr_timeout = stoi(value);
		} else if (name == "entry_timeout") {
			fs.opts.entry_timeout = stoi(value);
		} else if (name == "redirect_read_xattr") {
			redirect->read_xattr.push_back(value);
		} else if (name == "redirect_readdir_xattr") {
			redirect->readdir_xattr.push_back(value);
		} else if (name == "redirect_write_xattr") {
			redirect->write_xattr.push_back(value);
		} else if (name == "redirect_writedir_xattr") {
			redirect->writedir_xattr.push_back(value);
		} else if (name == "redirect_write_folder_id") {
			redirect->set_folder_id(value);
		} else if (name == "redirect_xattr_prefix") {
			redirect->xattr_prefixes.push_back(value);
		} else if (name == "redirect_op") {
			redirect->set_op(value);
		}
	}

	// create() also opens for write, so when configured to redirect
	// all opens for write we also need to redirect create()
	if (redirect->test_op(OP_OPEN_RW))
		redirect->set_op(OP_CREATE);

	fs.opts.debug = debug;

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

int main(int argc, char *argv[])
{
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
		fs.opts.debug = true;

	// We need an fd for every dentry in our the filesystem that the
	// kernel knows about. This is way more than most processes need,
	// so try to get rid of any resource softlimit.
	maximize_fd_limit();

	// Don't apply umask, use modes exactly as specified
	umask(0);

	// Initialize fuse
	fuse_args args = FUSE_ARGS_INIT(0, nullptr);
	if (fuse_opt_add_arg(&args, argv[0]) ||
			fuse_opt_add_arg(&args, "-o") ||
			fuse_opt_add_arg(&args, "allow_other,default_permissions,fsname=cachegw,subtype=cachegw") ||
			(fs.opts.kernel_passthrough &&
			 fuse_opt_add_arg(&args, "-onosuid,nodev")) ||
			(options.count("debug-fuse") &&
			 fuse_opt_add_arg(&args, "-odebug")))
		errx(3, "ERROR: Out of memory");

	cgwfs_assign_operations(fs.oper);

	// If we are not redirecting, do not register cachegwfs module
	int num_modules = !fs.redirect_path.empty();
	fuse_passthrough_module *modules[] = { &fs };

	return fuse_passthrough_main(&args, fs.opts, modules, num_modules, sizeof(fs.oper));
}
