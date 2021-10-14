/*
  cachegwfs: FUSE passthrough module

  Copyright (C) 2021       CTERA Networks

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
	OP_LINK,
	OP_RENAME,
	OP_UNLINK,
	OP_SYMLINK,
	OP_MKDIR,
	OP_MVDIR,
	OP_RMDIR,
	OP_MKNOD,
	OP_GETXATTR,
	OP_SETXATTR,
	OP_ALL,
};

const map<enum op, const char *> op_names = {
	{ OP_LOOKUP, "lookup" },
	{ OP_GETATTR, "getattr" },
	{ OP_OPEN_RO, "open_ro" },
	{ OP_OPEN_RW, "open_rw" },
	{ OP_OPENDIR, "opendir" },
	{ OP_SYMLINK, "symlink" },
	{ OP_STATFS, "statfs" },
	{ OP_CHMOD, "chmod" },
	{ OP_CHOWN, "chown" },
	{ OP_TRUNCATE, "truncate" },
	{ OP_UTIMENS, "utimens" },
	{ OP_MKDIR, "mkdir" },
	{ OP_MVDIR, "mvdir" },
	{ OP_RMDIR, "rmdir" },
	{ OP_MKNOD, "mknod" },
	{ OP_LINK, "link" },
	{ OP_RENAME, "rename" },
	{ OP_UNLINK, "unlink" },
	{ OP_GETXATTR, "getxattr" },
	{ OP_SETXATTR, "setxattr" },
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
	string read_xattr;
	string write_xattr;
	string readdir_xattr;
	vector<string> xattr_prefixes;
	set<enum op> ops; // fs operations to redirect

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

struct CgwFs : public fuse_passthrough_module {
	string source;
	string mountpoint;
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
static CgwFs cgwfs{};

#define next_op(op) call_module_next_op(cgwfs, op)


// Check if this is an empty place holder (a.k.a stub file).
// See: https://github.com/github/libprojfs/blob/master/docs/design.md#extended-attributes
static bool should_redirect_fd(int fd, const char *procname, enum op op)
{
	if (cgwfs.redirect_op(OP_ALL))
		return true;

	if (!cgwfs.redirect_op(op))
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

	auto r = cgwfs.redirect();
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
	bool redirect_op = cgwfs.redirect_op(op);
	if (redirect_op)
		n = readlink(in.proc_path(), linkname, PATH_MAX);

	int prefix = cgwfs.source.size();
	if (redirect_op && prefix && n >= prefix &&
	    !memcmp(cgwfs.source.c_str(), linkname, prefix) &&
	    should_redirect_fd(dirfd, in.proc_path(), op)) {
		linkname[n] = 0;
		auto outpath = cgwfs.redirect_path;
		if (cgwfs.redirect_path.empty())
			outpath.append(linkname);
		else
			outpath.append(linkname + prefix, n - prefix);
		if (!in.empty()) {
			outpath.append("/");
			outpath.append(name);
		}
		if (cgwfs.debug())
			cerr << "DEBUG: redirect " << op_name(op)
				<< " |=> " << outpath << endl;
		// Return redirected path
		return fuse_path_at_cwd(in, outpath.c_str());
	} else {
		// Return a copy of the path we got
		return in;
	}
}

static enum op redirect_open_op(int flags)
{
	return (flags & O_ACCMODE) == O_RDONLY ? OP_OPEN_RO : OP_OPEN_RW;
}

static int check_safe_fd(fuse_file_info *fi)
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
	enum op op = redirect_open_op(fi->flags);
	if (!should_redirect_fd(fd, NULL, op))
		return 0;

	cerr << "INFO: file open raced with evict." << endl;
	errno = EAGAIN;
	return -1;
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
			if (cgwfs.debug())
				cerr << "faccessat(" << out.path() << ", " << out.flags()
					<< "): " << strerror(errno) << endl;
			return -1;
		}
	}
	// Lookup itself is never in the redirected path, because we
	// need to find the real xfs inode
	return next_op(lookup)(at, e);
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
	return next_op(opendir)(out, fi);
}

static int cgwfs_create(const fuse_path_at &in, mode_t mode, fuse_file_info *fi)
{
	enum op op = redirect_open_op(fi->flags);
	auto out = get_fd_path_op(in, op);
	auto ret = next_op(create)(out, mode, fi);
	if (ret)
		return ret;

	// flock non-redirected fd
	auto redirected = (out.dirfd() == AT_FDCWD && !out.follow());
	if (!redirected && check_safe_fd(fi) == -1) {
		release_file(fi);
		return -1;
	}

	return 0;
}

static int cgwfs_open(const fuse_path_at &in, fuse_file_info *fi)
{
	enum op op = redirect_open_op(fi->flags);
	auto out = get_fd_path_op(in, op);
	auto ret = next_op(open)(out, fi);
	if (ret)
		return ret;

	// flock non-redirected fd
	auto redirected = (out.dirfd() == AT_FDCWD && !out.follow());
	if (!redirected && check_safe_fd(fi) == -1) {
		release_file(fi);
		return -1;
	}

	return 0;
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
	if (cgwfs.debug())
		cerr << "DEBUG: " << op_name(op) << " " << name << endl;

	// redirect xattr ops for names that match a redirect_xattr_prefix
	for (const auto& prefix : cgwfs.redirect()->xattr_prefixes) {
	    if (xattr_starts_with(name, prefix))
		return OP_REDIRECT;
	}

	// redirect implicit chmod/chown via setfacl
	if (op == OP_SETXATTR && (cgwfs.redirect_op(OP_CHMOD) || cgwfs.redirect_op(OP_CHOWN)) &&
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
		("nocache", "Disable all caching")
		("wbcache", "Enable writeback cache")
		("nosplice", "Do not use splice(2) to transfer data")
		("nokernpassthrough", "Do not use pass-through mode in kernel for read/write")
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

	cgwfs.opts.singlethread = options.count("single");
	cgwfs.opts.nosplice = options.count("nosplice");
	cgwfs.opts.nocache = options.count("nocache");
	cgwfs.opts.timeout = cgwfs.opts.nocache ? 0 : 1.0;
	cgwfs.opts.wbcache = !cgwfs.opts.nocache && options.count("wbcache");
	cgwfs.opts.kernel_passthrough = !options.count("nokernpassthrough");

	auto rp = realpath(argv[1], NULL);
	if (!rp)
		err(1, "ERROR: realpath(\"%s\")", argv[1]);
	cout << "source is " << rp << endl;
	cgwfs.source = rp;

	auto mp = realpath(argv[2], NULL);
	if (!mp) {
		cerr << "realpath(" << argv[2] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "mount point is " << mp << endl;
	cgwfs.mountpoint = mp;

	if (options.count("redirect_path")) {
		auto path = options["redirect_path"].as<string>();
		rp = realpath(path.c_str(), NULL);
		if (!rp)
			err(1, "ERROR: realpath(\"%s\")", path.c_str());
		cout << "redirect path is " << rp << endl;
		cgwfs.redirect_path = rp;
	}

	cgwfs.config_file = options["config_file"].as<string>();
	cout << "config file is " << cgwfs.config_file << endl;

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
	if (cgwfs.redirect_path.empty()) {
		// Redirect disabled with mount options
		return nullptr;
	}

	ifstream cFile(cgwfs.config_file);
	if (!cFile.is_open()) {
		if (cgwfs.config_file != CONFIG_FILE)
			cerr << "ERROR: Failed to open config file "
				<< cgwfs.config_file << endl;
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
		} else if (name == "redirect_xattr_prefix") {
			redirect->xattr_prefixes.push_back(value);
		} else if (name == "redirect_op") {
			redirect->set_op(value);
		}
	}

	cgwfs.opts.debug = debug;

	return redirect;
}

static void reload_config(int)
{
	// Request config reload
	cgwfs.reset_config();
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
	auto r = cgwfs.redirect();
	// Re-load config file on SIGHUP
	set_signal_handler();
	// These mount option settings are cleared on config file reload
	if (options.count("redirect"))
		r->set_op(OP_ALL);
	if (options.count("debug"))
		cgwfs.opts.debug = true;

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
			(cgwfs.opts.kernel_passthrough &&
			 fuse_opt_add_arg(&args, "-onosuid,nodev")) ||
			(options.count("debug-fuse") &&
			 fuse_opt_add_arg(&args, "-odebug")))
		errx(3, "ERROR: Out of memory");

	cgwfs.opts.source = cgwfs.source.c_str();
	cgwfs.opts.mountpoint = cgwfs.mountpoint.c_str();
	cgwfs.opts.foreground = true;
	cgwfs_assign_operations(cgwfs.oper);

	// If we are not redirecting, do not register cachegwfs module
	int num_modules = !cgwfs.redirect_path.empty();
	fuse_passthrough_module *modules[] = { &cgwfs };

	return fuse_passthrough_main(&args, cgwfs.opts, modules, num_modules,
				     sizeof(cgwfs.oper));
}
