/*
  FUSE passthrough: FUSE passthrough example module

  Copyright (C) 2021-2024  CTERA Networks

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

/** @file
 *
 * This is an example of a simple passthrough module that adds debug prints
 * to a passthrough filesystem.  It is provided as an example for how to extend
 * the functionality of a passthrough filesystem using a module.
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

#include "../fuse_passthrough.h"
#include "../fuse_modules.h"


struct Trace : public fuse_passthrough_module {
	Trace();
};
static Trace trace{};

#define next_op(op) call_module_next_op(trace, op)

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

Trace::Trace() : fuse_passthrough_module("trace")
{
	assign_operations(oper);
}

fuse_passthrough_module *trace_module(void)
{
	return (fuse_passthrough_module *)&trace;
}
