/*
  FUSE passthrough: FUSE passthrough library

  Copyright (C) 2021-2024  CTERA Networks

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#ifndef FUSE_PASSTHROUGH_H_
#define FUSE_PASSTHROUGH_H_

/** @file
 *
 * FUSE passthrough library API
 *
 * ## Source code ##
 */

#include <string>
#include <memory>

#include <fuse.h>
#include <fuse_lowlevel.h>

struct fuse_passthrough_opts {
	std::string source;
	std::string mountpoint;
	double attr_timeout{0.0};
	double entry_timeout{0.0};
	bool nosplice{false};
	bool nocache{false};
	bool wbcache{false};
	bool async_flush{false};
	bool singlethread{false};
	bool foreground{false};
	bool clone_fd{true};
	bool keep_fd{false};
	bool connected_fd{false};
	bool debug{false};
	unsigned int max_threads{0};
	unsigned int max_idle_threads{0};
	bool kernel_passthrough{true};
	bool readdir_passthrough{false};
};

struct fuse_passthrough_module;
struct fuse_inode;
struct file_handle;

typedef std::shared_ptr<void> fuse_state_t;
typedef bool (*fuse_fill_state_t)(const fuse_inode &inode,
				  fuse_state_t &state, void *data);

struct fh_encoder {
	virtual int ino_size() const = 0;
	virtual ino_t ino(struct file_handle &fh) const = 0;
	virtual uint32_t gen(struct file_handle &fh) const = 0;
	virtual ino_t parent_ino(struct file_handle &fh) const = 0;
	virtual uint32_t parent_gen(struct file_handle &fh) const = 0;
	virtual ino_t nodeid(struct file_handle &fh) const = 0;
	virtual void encode(struct file_handle &fh, ino_t ino, uint32_t gen) const = 0;
	virtual bool is_connectable(const struct file_handle &fh) const = 0;
	virtual bool make_connectable(struct file_handle &fh,
				      const struct file_handle &parent_fh) const = 0;
	virtual bool get_parent_fh(const struct file_handle &fh,
				   struct file_handle &parent_fh) const = 0;
	virtual ~fh_encoder() {}
};

struct fuse_inode {
	virtual int get_fd() const = 0;
	virtual void open_fd() = 0;
	virtual void close_fd() = 0;
	virtual fuse_state_t& get_state(const fuse_passthrough_module &module) = 0;

	virtual ino_t ino() const = 0;
	virtual ino_t gen() const = 0;
	virtual ino_t nodeid() const = 0;
	virtual file_handle *get_file_handle() const = 0;

	virtual bool is_dir() const = 0;
	virtual bool is_regular() const = 0;
	virtual bool is_symlink() const = 0;
	virtual bool is_special() const = 0;
	virtual bool is_dead() const = 0;
	virtual bool is_root() const = 0;

	virtual ~fuse_inode() {};
};

/*
 * Store/fetch a generic state object per module per inode.
 *
 * The module is responsible of allocating the object referenced
 * by the shared_ptr, but the object is desctructed automatically.
 *
 * The optional @filler callback can be used to initialize
 * a new state object or to update an existing state object.
 * Note that @filler is called with inode mutex held, so it
 * should not call back into default passthrough methods.
 */
bool get_module_inode_state(const fuse_passthrough_module &module,
			    fuse_ino_t ino, fuse_state_t &ret_state,
			    fuse_fill_state_t filler = NULL,
			    void *data = NULL);
bool set_module_inode_state(const fuse_passthrough_module &module,
			    fuse_ino_t ino, const fuse_state_t &new_state,
			    bool excl = false);
bool clear_module_inode_state(const fuse_passthrough_module &module,
			      fuse_ino_t ino);

struct fuse_path_at {
	/*
	 * By default, @path is relative to inode's fd and may be empty.
	 * With @at_cwd true, @path is relative to AT_FDCWD.
	 * With @magic true, @path is a magic symlink.
	 * If @path is empty and @at_cwd is true, fuse_path_at is initialized
	 * with the magic symlink of the inode's fd.
	 */
	fuse_path_at(fuse_req_t req, fuse_inode &inode, const char *path,
		     bool at_cwd = false, bool magic = false) :
		_req(req), _inode(inode), _path(path), _magic(magic) {
		init_path(at_cwd);
	}
	fuse_path_at(const fuse_path_at &at) :
		_req(at._req), _inode(at._inode), _path(at._path),
		_magic(at.is_magic()) {
		init_path(at.cwd());
	}
	virtual ~fuse_path_at() {}

	virtual int dirfd() const {
		return _dirfd;
	}
	virtual int cwd() const {
		return _dirfd == AT_FDCWD;
	}
	virtual bool empty() const {
		return _path.empty();
	}
	virtual const char *path() const {
		return _path.c_str();
	}

	/*
	 * The AT_* flags to be used for different *at() syscalls depending on
	 * whether the syscall defaults to follow symlinks (e.g. fstatat()) or
	 * not (e.g. linkat()).
	 */
	virtual int flags(bool default_follow = true) const
	{
		int flags = 0;

		if (empty())
			flags |= AT_EMPTY_PATH;

		if (follow() == default_follow)
			return flags;

		return flags | (default_follow ?
				AT_SYMLINK_NOFOLLOW : AT_SYMLINK_FOLLOW);
	}

	/* Need to use "follow" syscalls for magic symlink */
	virtual bool follow() const { return _magic; }
	virtual bool is_magic() const { return _magic; }
	virtual fuse_req_t req() const { return _req; }
	virtual fuse_inode& inode() const { return _inode; }
	virtual const char *proc_path() const { return _proc_path; }

	virtual void print_fd_path(const char *caller) const;
	virtual bool is_connected() const;
	virtual bool reconnect() const;
private:
	fuse_req_t _req;
	fuse_inode &_inode;
	std::string _path;
	int _dirfd;
	bool _magic;
	char _proc_path[64];

	/* @at_cwd initializes path for syscalls that do not support dirfd */
	void init_path(bool at_cwd)
	{
		_proc_path[0] = 0;
		_dirfd = _inode.get_fd();
		if (_dirfd >= 0)
			sprintf(_proc_path, "/proc/self/fd/%i", _dirfd);

		if (at_cwd) {
			_dirfd = AT_FDCWD;
			if (_path.empty()) {
				_magic = true;
				_path = _proc_path;
			}
		}
	}
};

/* Path to be used for syscalls that take an fd argument */
struct fuse_fd_path_at : fuse_path_at {
	fuse_fd_path_at(fuse_req_t req, fuse_inode &inode,
			struct fuse_file_info *fi) :
		fuse_path_at(req, inode, ""), file(fi) {}

	struct fuse_file_info *file;
};

/* Path to be used for syscalls that take dirfd with empty path */
struct fuse_empty_path_at : fuse_path_at {
	fuse_empty_path_at(fuse_req_t req, fuse_inode &inode);
};

/* String the name from dirfd+name */
struct fuse_parent_path_at : fuse_path_at {
	fuse_parent_path_at(const fuse_path_at &at) :
		fuse_path_at(at.req(), at.inode(), "") {}
};

/* Path to be used for syscalls that do not take dirfd or empty path */
struct fuse_path_at_cwd : fuse_path_at {
	fuse_path_at_cwd(const fuse_path_at &at) :
		fuse_path_at(at.req(), at.inode(), at.path(), true,
			     at.is_magic()) {}
	fuse_path_at_cwd(const fuse_path_at &at, const char *path) :
		fuse_path_at(at.req(), at.inode(), path, true) {}
};

void __trace_fd_path_at(const fuse_path_at &in, const char *caller);

#define trace_fd_path_at(in) \
	__trace_fd_path_at((in), __func__)

/*
 * Abstract fi->fh object for an open FUSE passthrough file or directory
 */
struct fuse_file {
	virtual int get_fd() = 0;
	virtual fuse_state_t& get_state(const fuse_passthrough_module &module) = 0;

	virtual ~fuse_file() {}
};

static inline fuse_file *get_file(fuse_file_info *fi)
{
	return reinterpret_cast<fuse_file*>(fi->fh);
}

static inline int get_file_fd(fuse_file_info *fi)
{
	return get_file(fi)->get_fd();
}

static inline fuse_state_t& get_file_state(fuse_file_info *fi,
					   const fuse_passthrough_module &module)
{
	return get_file(fi)->get_state(module);
}

static inline void release_file(fuse_file_info *fi)
{
	auto fh = get_file(fi);
	delete fh;
	fi->fh = 0;
}

/**
 * The passthrough filesystem operations:
 *
 * These operations are similar to fuse_operations except the const char *path
 * argument type replaced with the extended fuse_path_at reference that makes
 * more context available about the referenced filesystem object.
 *
 * Unlike the fuse_operations, most operations return -1 and set errno on
 * failure like the respective libc operations.
 *
 * All methods are optional for a passthrough module.
 * Methods that are not implemented by a passthrough module will use the default
 * passthrough library implementation.  Typically, the passthrough module method
 * implementation takes some action and calls the next module's method, finally
 * calling the default passthrough library implementation of the method.
 */
struct fuse_passthrough_operations {

	/*
	 * The lookup() operation is an exception because it correspond to a
	 * low-level operation, whereas other passthrough operations correspond
	 * to high-level operations.
	 *
	 * It can be used by a passthrough module, such as HSM, to manifest
	 * the file is source directory before the actual passthrough lookup.
	 */
	int (*lookup) (const fuse_path_at &, fuse_entry_param *);
	int (*getattr) (const fuse_path_at &, struct stat *,
			struct fuse_file_info *);
	int (*chmod) (const fuse_path_at &, mode_t, struct fuse_file_info *);
	int (*chown) (const fuse_path_at &, uid_t, gid_t,
			struct fuse_file_info *);
	int (*truncate) (const fuse_path_at &, off_t, struct fuse_file_info *);
	int (*utimens) (const fuse_path_at &, const struct timespec tv[2],
			struct fuse_file_info *);
	int (*mknod) (const fuse_path_at &, mode_t, dev_t);
	int (*mkdir) (const fuse_path_at &, mode_t);
	int (*unlink) (const fuse_path_at &);
	int (*rmdir) (const fuse_path_at &);
	int (*symlink) (const char *, const fuse_path_at &);
	int (*readlink) (const fuse_path_at &, char *, size_t);
	int (*rename) (const fuse_path_at &, const fuse_path_at &,
			unsigned int);
	int (*link) (const fuse_path_at &, const fuse_path_at &);
	int (*setxattr) (const fuse_path_at &, const char *, const char *,
			size_t, int);
	int (*getxattr) (const fuse_path_at &, const char *, char *, size_t);
	int (*listxattr) (const fuse_path_at &, char *, size_t);
	int (*removexattr) (const fuse_path_at &, const char *);
	int (*statfs) (const fuse_path_at &, struct statvfs *);
	/*
	 * A passthrough module may store a concrete object that implements
	 * the fuse_file interface in fi->fh or call the default library
	 * implementation to store the internal File object.
	 *
	 * In either case, all operations that operate on fi->fh, will be able
	 * to use the helpers get_file() release_file() and get_file_fd() to
	 * perform operations on the open file.
	 */
	int (*open) (const fuse_path_at &, struct fuse_file_info *);
	int (*create) (const fuse_path_at &, mode_t, struct fuse_file_info *);
	/*
	 * By default, all I/O on open files is performed by the passthrough
	 * library (or the kernel).  To intercept I/O, the module needs to
	 * implement the {read,write}_buf() operations and clear any of the
	 * fi->passthrough_{read,write} flags on open().
	 */
	int (*read_buf) (const fuse_path_at &, struct fuse_bufvec **,
			 size_t, off_t, struct fuse_file_info *);
	int (*write_buf) (const fuse_path_at &, struct fuse_bufvec *, off_t,
			  struct fuse_file_info *);
	ssize_t (*copy_file_range) (const fuse_path_at &,
				    struct fuse_file_info *, off_t,
				    const fuse_path_at &,
				    struct fuse_file_info *, off_t,
				    size_t, int);
	int (*flush) (const fuse_path_at &, struct fuse_file_info *);
	int (*release) (const fuse_path_at &, struct fuse_file_info *);
	int (*fsync) (const fuse_path_at &, int, struct fuse_file_info *);
	int (*flock) (const fuse_path_at &, struct fuse_file_info *, int);
	off_t (*lseek) (const fuse_path_at &, off_t, int,
			struct fuse_file_info *);
	int (*fallocate) (const fuse_path_at &, int, off_t, off_t,
			  struct fuse_file_info *);
	/*
	 * The flag fi->passthrough_readdir/plus can be set to indicate that
	 * readdir() can be performed by the library (or kernel) without calling
	 * the module readdir() operation.
	 */
	int (*opendir) (const fuse_path_at &, struct fuse_file_info *);
	/*
	 * By default, readdir on open directory is performed by the passthrough
	 * library (or the kernel).  To intercept readdir() or stat(), the module
	 * needs to implement the readdir() operation and clear the
	 * fi->passthrough_readdir/plus flag on opendir().
	 */
	int (*readdir) (const fuse_path_at &, void *, fuse_fill_dir_t, off_t,
			struct fuse_file_info *, enum fuse_readdir_flags);
	int (*releasedir) (const fuse_path_at &, struct fuse_file_info *);
	int (*fsyncdir) (const fuse_path_at &, int, struct fuse_file_info *);
};


struct fuse_passthrough_module {
	fuse_passthrough_module(const char *_name) : name(_name) {}
	virtual ~fuse_passthrough_module() {}

	virtual bool debug() { return opts.debug; }

        const char *name;
	fuse_passthrough_opts opts{};
	fuse_passthrough_operations oper{};
	fuse_passthrough_operations next{};
	int idx{0};
};

#define __call_op(op) \
	(!op) ? (errno = EOPNOTSUPP, -1) : op

#define call_module_next_op(module, op) \
	__call_op((module).next.op)

int fuse_passthrough_main(fuse_args *args, fuse_passthrough_opts &opts,
			  fuse_passthrough_module *modules[], int num_modules,
			  size_t oper_size);

#endif /* FUSE_PASSTHROUGH_H_ */
