subdir('lib/ght/ght')

ssp_src = files(
    'src/ssp.c',
    'src/ssp_tcp.c'
)
ssp_include = include_directories('include/')

libssp = library('ssp', ssp_src, 
    include_directories: [
        ssp_include,
        ght_include
    ],
    link_with: [
        libght
    ]
)
