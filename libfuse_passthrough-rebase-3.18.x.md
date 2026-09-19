# libfuse_passthrough rebase onto fuse-3.18.x

Folding later `notifyfs` library work into the original `libfuse_passthrough` series while rebasing onto `fuse-3.18.x`. `cachegwfs:*` / `notifyfs:*` module commits stay out of this branch.

## Test infra

Python example tests were replaced upstream by the shell runner (`test/run-tests.py` + `test/cases/*.sh`).

- Dropped `test/test_examples.py` instead of porting it.
- Added shell cases: `passthrough-fs.sh`, `passthrough-fs-debug.sh`, `passthrough-fs-wbcache.sh`, `passthrough-fs-nocache.sh`, `passthrough-fs-nopassthrough.sh` (and hp `nopassthrough` / `nocache` variants).
- `passthrough_fs` tests run as root (kernel passthrough / `AT_EMPTY_PATH` / open-by-handle). Do not “fix” `linkat(AT_EMPTY_PATH)` ENOENT by switching to `/proc/self/fd` in `passthrough_fs`.

## notifyfs library changes already folded

| notifyfs | Folded into (original series) | What |
|---|---|---|
| `14820f6f` allow modules to clean page cache on open | `3f4f56dc` create library; kernel PT `cfc52ba5` | `fi->keep_cache` / `cache_readdir` / `noflush` set before `call_op(open)` / `call_op(opendir)`; kernel PT then sets `keep_cache`/`cache_readdir` false |
| `ada21597` (forget hook only) | `3f4f56dc` | `oper.forget` / `do_forget` / `call_op(forget)` without module state |
| `3a6d7834` race between forget_one and do_lookup | `3f4f56dc` | `atomic nlookup`; increment under `fs.m` before unlock; re-check nlookup in `do_forget`; `unique_lock` + `l.release()` |
| `e000ee69` take fs.m when link() raises nlookup | `3f4f56dc` | `pfs_link()` increments `nlookup` under `fs.m` |
| *(forget fd)* | `3f4f56dc` | `InodeRef(..., openfd=false)` so FORGET does not open an O_PATH fd (`fd` stays `-1`) |
| `08783652` (library half) | `3f4f56dc` | shared opts: `fuse_passthrough_get_opts()`, drop per-module `opts`, drop `opts` arg from `fuse_passthrough_main()` |
| `aa519259` allow configuring negative_timeout | `3f4f56dc` | `negative_timeout` defaults to 0; ENOENT uses it instead of `entry_timeout` |
| `4de90adf` invalidate file type on inode number reuse | `5b822a30` store persistent file handle | `inode.set_ftype()` on generation mismatch |
| `482009f2` auto-enable keepfd if bulkstat is not allowed | `5b822a30` | `EPERM` from bulkstat → `keep_fd = 1` instead of fatal |
| `1b978db6` AT_HANDLE_CONNECTABLE does not allow AT_EMPTY_PATH | `80f30a82` compose and reconnect | `name_to_handle_at(".", connectable)` for root; lookup uses dirfd+name when parent is known |
| `38233f89` add debug prints for reconnect() | `80f30a82` | extra debug on missing parent fh, fdopendir, missing child, reconnect result |
| `7627bec0` fix implementation of async_flush | `db638de7` | invert `pfs_oper.flush` so sync FLUSH runs when async_flush is off; default `async_flush{true}` |
| `2a142be3` fix opt-out of read/write passthrough | `cfc52ba5` kernel PT r/w | on module opt-out, set `fi->backing_id` to the inode's shared backing id and `keep_cache=false` plus DIO |
| `00ae6444` fix library passthrough of read/write/readdir | `abb025db` per-file opt-out | store `passthrough_{read,write}` on `fuse_file` / Dir; `pfs_read`/`pfs_write_buf`/`pfs_readdir` use those, not `fi` |
| `f5907122` add access operation support | new commit after kernel PT readdir | `pfs_access` / `do_access`; `def_permissions` / `def_posixacl`; `--nopermcache` / `--posixacl` |
| `7f470292` + `619c4283` `with_cred()` / posixacl | new commit after access | `fuse_path_at::with_cred` / `with_cred_force`; skip creds when `def_posixacl` |

`ada21597` / `4cff5b8e` inode/file state APIs replay as themselves in the series.

Skipped: `af63dba6` (kernel vs. server killpriv).

## TODO: FUSE-over-io-uring

- [x] `pfs_init()` uses `fuse_set_feature_flag` / `fuse_unset_feature_flag`
      (no `conn->want` assignment, does not clear `FUSE_CAP_OVER_IO_URING`).
- [x] No new `passthrough-fs*.sh` files; `--io-uring` reuses the existing cases.
- [x] `--io-uring` suite passed on kernel 7.0 while the series was on `master`.
- [ ] Re-run `--io-uring` after the next rebase onto `master`.
- [ ] Optional: `FUSE_CONN_FLAG_SINGLE_ISSUER` only after that rebase
      (not in 3.18 headers).

## TODO: CI

- [x] `passthrough-fs*.sh` call `_require_root`, so non-root jobs SKIP instead
      of FAIL on `linkat(AT_EMPTY_PATH)`.
- [x] `build_passthrough` is Linux-only, so FreeBSD `ninja` does not link
      `passthrough_fs` against a missing library.
- [ ] checkpatch fails on most C++ commits: it reads `auto &x` / `Type &ref`
      as bad `&` spacing and `template<>` as bad `<`/`>` spacing, and
      `checkpatch.yml` fails on any WARNING. Ask upstream to add those types
      to IGNORES or to exclude `passthrough/*.cpp`; do not reformat C++ to
      satisfy a C checker. `FUNCTION_WITHOUT_ARGS` / `BLOCK_COMMENT_STYLE` are
      real and worth fixing. Re-run
      `./.github/workflows/run-checkpatch.sh <commit>` per commit before the PR.
- [ ] `clang-san-m32` builds the C++ library at `-m32` with `-Dwerror=true`.
      Not reproducible here without 32-bit libstdc++ (`add_languages('cpp')`
      returns false and the passthrough subdir is skipped). Install
      `g++-multilib` and rebuild — 32-bit `ino_t` / `off_t` /
      `struct file_handle` are the risk.
- [ ] Sanitizer + root: `test/ci-build.sh --root --sanitize` (needs sudo;
      LeakSanitizer sees the `new File` / inode allocations).
- [ ] `codespell` over `passthrough/` and the new markdown.

