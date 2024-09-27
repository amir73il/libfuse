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

using namespace std;


enum op {
	OP_REDIRECT, // Force redirect
	OP_LOOKUP,
	OP_GETATTR,
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
};

const map<enum op, const char *> op_names = {
	{ OP_LOOKUP, "lookup" },
	{ OP_GETATTR, "getattr" },
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
	string read_xattr;
	string write_xattr;
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
		return redirect_all || op == OP_REDIRECT || r->test_op(op);
	}
	bool redirect_all{false};

private:
	atomic_flag config_is_valid {ATOMIC_FLAG_INIT};
	shared_ptr<Redirect> _redirect;
};
static CgwFs cgwfs{};


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
		("nopassthrough", "Do not use pass-through mode in kernel for read/write")
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

	cgwfs.opts.debug = options.count("debug");
	cgwfs.opts.foreground = options.count("foreground");
	cgwfs.opts.singlethread = options.count("single");
	cgwfs.redirect_all = options.count("redirect");
	cgwfs.opts.nosplice = options.count("nosplice");
	cgwfs.opts.nocache = options.count("nocache");
	cgwfs.opts.timeout = cgwfs.opts.nocache ? 0 : 1.0;
	cgwfs.opts.wbcache = !cgwfs.opts.nocache && options.count("wbcache");
	cgwfs.opts.kernel_passthrough = !options.count("nopassthrough");

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
		cerr << "ERROR: Open config file failed." << endl;
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
			redirect->read_xattr = value;
			redirect->set_op(OP_OPEN_RO);
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
	(void)cgwfs.redirect();
	// Re-load config file on SIGHUP
	set_signal_handler();

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

	fuse_passthrough_module *modules[] = {};

	return fuse_passthrough_main(&args, cgwfs.opts, modules, 0,
				     sizeof(cgwfs.oper));
}
