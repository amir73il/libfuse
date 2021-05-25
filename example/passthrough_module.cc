/*
  FUSE passthrough: FUSE passthrough example module

  Copyright (C) 2021-2024  CTERA Networks

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This is an example of a simple passthrough filesystem, where the
 * passthrough functionality is implemented by libfuse_passthrough.
 *
 * On its own, this filesystem only adds debug prints and fulfills no
 * other practical purpose.  It is intended as an example for how to
 * extend the functionality of a passthrough filesystem using a module.
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
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <fuse.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

// C++ includes
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <list>
#include "cxxopts.hpp"
#include <fstream>
#include <thread>

#include "fuse_passthrough.h"

using namespace std;


struct Module : public fuse_passthrough_module {
	Module() : fuse_passthrough_module("example") {}

	string source;
	string mountpoint;
};
static Module module{};

#define next_op(op) call_module_next_op(module, op)


static int xmp_getattr(const fuse_path_at &at, struct stat *attr,
			 fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(getattr)(at, attr, fi);
}

static int xmp_chmod(const fuse_path_at &at, mode_t mode, fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(chmod)(at, mode, fi);
}

static int xmp_chown(const fuse_path_at &at, uid_t uid, gid_t gid,
		       fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(chown)(at, uid, gid, fi);
}

static int xmp_truncate(const fuse_path_at &at, off_t size, fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(truncate)(at, size, fi);
}

static int xmp_utimens(const fuse_path_at &at, const struct timespec tv[2],
			 struct fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(utimens)(at, tv, fi);
}

static int xmp_mkdir(const fuse_path_at &at, mode_t mode)
{
	trace_fd_path_at(at);
	return next_op(mkdir)(at, mode);
}

static int xmp_symlink(const char *link, const fuse_path_at &at)
{
	trace_fd_path_at(at);
	return next_op(symlink)(link, at);
}

static int xmp_mknod(const fuse_path_at &at, mode_t mode, dev_t rdev)
{
	trace_fd_path_at(at);
	return next_op(mknod)(at, mode, rdev);
}

static int xmp_link(const fuse_path_at &oldat, const fuse_path_at &newat)
{
	__trace_fd_path_at(oldat, "link_src");
	__trace_fd_path_at(newat, "link_dst");
	return next_op(link)(oldat, newat);
}

static int xmp_rmdir(const fuse_path_at &at)
{
	trace_fd_path_at(at);
	return next_op(rmdir)(at);
}

static int xmp_rename(const fuse_path_at &oldat, const fuse_path_at &newat,
			unsigned int flags)
{
	__trace_fd_path_at(oldat, "rename_src");
	__trace_fd_path_at(newat, "rename_dst");
	return next_op(rename)(oldat, newat, flags);
}

static int xmp_unlink(const fuse_path_at &at)
{
	trace_fd_path_at(at);
	return next_op(unlink)(at);
}

static int xmp_opendir(const fuse_path_at &at, fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(opendir)(at, fi);
}

static int xmp_create(const fuse_path_at &at, mode_t mode, fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(create)(at, mode, fi);
}

static int xmp_open(const fuse_path_at &at, fuse_file_info *fi)
{
	trace_fd_path_at(at);
	return next_op(open)(at, fi);
}

static int xmp_statfs(const fuse_path_at &at, struct statvfs *stbuf)
{
	trace_fd_path_at(at);
	return next_op(statfs)(at, stbuf);
}

static int xmp_getxattr(const fuse_path_at &at, const char *name, char *value,
			  size_t size)
{
	trace_fd_path_at(at);
	return next_op(getxattr)(at, name, value, size);
}

static int xmp_listxattr(const fuse_path_at &at, char *value, size_t size)
{
	trace_fd_path_at(at);
	return next_op(listxattr)(at, value, size);
}

static int xmp_setxattr(const fuse_path_at &at, const char *name,
			  const char *value, size_t size, int flags)
{
	trace_fd_path_at(at);
	return next_op(setxattr)(at, name, value, size, flags);
}

static int xmp_removexattr(const fuse_path_at &at, const char *name)
{
	trace_fd_path_at(at);
	return next_op(removexattr)(at, name);
}

static ssize_t xmp_copy_file_range(const fuse_path_at &at_in,
				struct fuse_file_info *fi_in, off_t off_in,
				const fuse_path_at &at_out,
				struct fuse_file_info *fi_out, off_t off_out,
				size_t len, int flags)
{
	__trace_fd_path_at(at_in, "copy_src");
	__trace_fd_path_at(at_out, "copy_dst");
	return next_op(copy_file_range)(at_in, fi_in, off_in,
					at_out, fi_out, off_out, len, flags);
}


static void assign_operations(fuse_passthrough_operations &oper)
{
	oper.mkdir = xmp_mkdir;
	oper.mknod = xmp_mknod;
	oper.symlink = xmp_symlink;
	oper.link = xmp_link;
	oper.unlink = xmp_unlink;
	oper.rmdir = xmp_rmdir;
	oper.rename = xmp_rename;
	oper.getattr = xmp_getattr;
	oper.chmod = xmp_chmod;
	oper.chown = xmp_chown;
	oper.truncate = xmp_truncate;
	oper.utimens = xmp_utimens;
	oper.opendir = xmp_opendir;
	oper.create = xmp_create;
	oper.open = xmp_open;
	oper.statfs = xmp_statfs;
	oper.setxattr = xmp_setxattr;
	oper.getxattr = xmp_getxattr;
	oper.listxattr = xmp_listxattr;
	oper.removexattr = xmp_removexattr;
	oper.copy_file_range = xmp_copy_file_range;
}


static void print_usage(char *prog_name) {
	cout << "Usage: " << prog_name << " --help\n"
		<< "       " << prog_name << " [options] <source> <mountpoint>\n";
}

static cxxopts::ParseResult parse_wrapper(cxxopts::Options& parser, int& argc, char**& argv) {
	try {
		return parser.parse(argc, argv);
	} catch (cxxopts::option_not_exists_exception& exc) {
		cout << argv[0] << ": " << exc.what() << endl;
		print_usage(argv[0]);
		exit(2);
	}
}


static cxxopts::ParseResult parse_options(int &argc, char **argv) {
	cxxopts::Options opt_parser(argv[0]);
	opt_parser.add_options()
		("debug", "Enable filesystem debug messages")
		("debug-fuse", "Enable libfuse debug messages")
		("foreground", "Run in foreground")
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
		cout << endl << "options:"
			<< help.substr(help.find("\n\n") + 1, string::npos);
		exit(0);

	} else if (argc < 3) {
		cout << argv[0] << ": invalid number of arguments\n";
		print_usage(argv[0]);
		exit(2);
	}

	module.opts.debug = options.count("debug");
	module.opts.foreground = options.count("foreground");
	module.opts.singlethread = options.count("single");
	module.opts.nosplice = options.count("nosplice");
	module.opts.nocache = options.count("nocache");
	module.opts.timeout = module.opts.nocache ? 0 : 1.0;
	module.opts.wbcache = !module.opts.nocache && options.count("wbcache");

	auto rp = realpath(argv[1], NULL);
	if (!rp) {
		cerr << "realpath(" << argv[1] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "source is " << rp << endl;
	module.source = rp;

	auto mp = realpath(argv[2], NULL);
	if (!mp) {
		cerr << "realpath(" << argv[2] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "mount point is " << mp << endl;
	module.mountpoint = mp;

	return options;
}

int main(int argc, char *argv[]) {

	// Parse command line options
	auto options {parse_options(argc, argv)};
	auto mount_options = "fsname=" + module.source + ",allow_other,default_permissions";

	// Initialize fuse
	fuse_args args = FUSE_ARGS_INIT(0, nullptr);
	if (fuse_opt_add_arg(&args, argv[0]) ||
			fuse_opt_add_arg(&args, "-o") ||
			fuse_opt_add_arg(&args, mount_options.c_str()) ||
			(options.count("debug-fuse") && fuse_opt_add_arg(&args, "-odebug")))
		errx(3, "ERROR: Out of memory");

	module.opts.source = module.source.c_str();
	module.opts.mountpoint = module.mountpoint.c_str();
	assign_operations(module.oper);
	// If we are not printing any traces, let the passthrough library take care
	// of everything
	auto mod = (module.opts.debug ? &module : NULL);

	return fuse_passthrough_main(&args, module.opts, mod, sizeof(module.oper));
}

