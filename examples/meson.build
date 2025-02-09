#tcp_client_src = files('tcp_client.c')
#tcp_server_src = files('tcp_server.c')

uft_client_src = files(
    'udp_file_transfer/uft_client.c',
    'udp_file_transfer/udp_common.c'
)
uft_server_src = files(
    'udp_file_transfer/uft_server.c',
    'udp_file_transfer/udp_common.c'
)
uft_include = include_directories('udp_file_transfer/')

links = [libssp, libght, libcutils]
include_dirs = [ssp_include, ght_include, uft_include, cutils_include]

executable('uft_client', uft_client_src, 
    include_directories: include_dirs,
    link_with: links
)

executable('uft_server', uft_server_src, 
    include_directories: include_dirs,
    link_with: links
)

#executable('tcp_client', tcp_client_src, 
#include_directories: include_dirs,
#link_with: links
#)

#executable('tcp_server', tcp_server_src, 
#include_directories: include_dirs,
#link_with: links
#)

