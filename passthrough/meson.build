lib = 'fuse_passthrough'
libfuse_passthrough_sources = [ lib + '.cpp', lib + '.h' ,
                                'modules/trace.cpp', 'fuse_modules.h' ]

libfuse_passthrough = library(lib, libfuse_passthrough_sources,
                  version: meson.project_version(),
                  soversion: '3', include_directories: include_dirs,
                  cpp_args : '-std=c++17',
                  dependencies: libfuse_dep, install: true)

pkg = import('pkgconfig')
pkg.generate(libraries: [ libfuse_passthrough, '-lpthread' ],
             libraries_private: '-ldl',
             version: meson.project_version(),
             name: lib,
             description: 'Passthrough Filesystem in Userspace',
             subdirs: 'fuse3')


