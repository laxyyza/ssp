ssp_src = files(
    'src/ssp.c',
    'src/ssp_tcp.c',
    'src/ssp_ring.c',
)
ssp_include = include_directories('include/')

zstd_dep = dependency('zstd', modules: ['zstd::libzstd'], required: true)

libssp = library('ssp', ssp_src, 
    include_directories: [
        ssp_include,
        ght_include,
        cutils_include,
    ],
    link_with: [
        libght
    ],
    dependencies: [zstd_dep]
)
