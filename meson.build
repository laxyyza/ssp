project('ssp', 'c',
    default_options: [
        'werror=true',
        'warning_level=2'
    ]
)

ssp_src = files(
    'src/ssp.c',
    'src/ssp_tcp.c'
)
ssp_include = include_directories('include/')

test_client_src = files('tests/client.c')

libssp = library('ssp', ssp_src, include_directories: ssp_include)

executable('test_client', test_client_src, include_directories: ssp_include,
    link_with: [
        libssp
    ]
)
