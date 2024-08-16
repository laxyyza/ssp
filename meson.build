project('ssp', 'c',
    default_options: [
        'werror=true',
        'warning_level=2',
    ]
)

subdir('lib/ght/ght')

ssp_src = files(
    'src/ssp.c',
    'src/ssp_tcp.c'
)
ssp_include = include_directories('include/')

test_client_src = files('tests/client.c')
test_server_src = files('tests/server.c')

libssp = library('ssp', ssp_src, include_directories: ssp_include)

executable('test_client', test_client_src, include_directories: ssp_include,
    link_with: [
        libssp
    ]
)

executable('test_server', test_server_src, 
    include_directories: [
        ssp_include, 
        ght_include
    ],
    link_with: [
        libssp,
        libght
    ]
)
