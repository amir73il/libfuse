/*
  FUSE passthrough: FUSE passthrough filesystem example

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

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 12)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// C includes
#include <err.h>
#include <errno.h>
#include <fuse.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
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
#include "fuse_modules.h"

using namespace std;


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


static cxxopts::ParseResult parse_options(int &argc, char **argv, fuse_passthrough_opts &opts) {
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

	opts.debug = options.count("debug");
	opts.foreground = options.count("foreground");
	opts.singlethread = options.count("single");
	opts.nosplice = options.count("nosplice");
	opts.nocache = options.count("nocache");
	opts.wbcache = !opts.nocache && options.count("wbcache");
	opts.attr_timeout = opts.entry_timeout = opts.nocache ? 0 : 1.0;

	auto rp = realpath(argv[1], NULL);
	if (!rp) {
		cerr << "realpath(" << argv[1] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "source is " << rp << endl;
	opts.source = rp;

	auto mp = realpath(argv[2], NULL);
	if (!mp) {
		cerr << "realpath(" << argv[2] << ") failed: " << strerror(errno) << endl;
		exit(1);
	}
	cout << "mount point is " << mp << endl;
	opts.mountpoint = mp;

	return options;
}

int main(int argc, char *argv[]) {

	// Parse command line options
	fuse_passthrough_opts opts{};
	auto options {parse_options(argc, argv, opts)};
	auto mount_options = "fsname=" + opts.source + ",allow_other,default_permissions";

	// Initialize fuse
	fuse_args args = FUSE_ARGS_INIT(0, nullptr);
	if (fuse_opt_add_arg(&args, argv[0]) ||
			fuse_opt_add_arg(&args, "-o") ||
			fuse_opt_add_arg(&args, mount_options.c_str()) ||
			(options.count("debug-fuse") && fuse_opt_add_arg(&args, "-odebug")))
		errx(3, "ERROR: Out of memory");

	// If we are not printing any traces, let the passthrough library take care
	// of everything
	auto mod = (opts.debug ? trace_module() : NULL);

	return fuse_passthrough_main(&args, opts, mod, sizeof(fuse_passthrough_operations));
}
