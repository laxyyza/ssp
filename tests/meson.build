tcp_client_src = files('tcp_client.c')
tcp_server_src = files('tcp_server.c')
udp_client_src = files('udp_client.c')
udp_server_src = files('udp_server.c')

links = [libssp, libght]
include_dirs = [ssp_include, ght_include]

executable('udp_client', udp_client_src, 
    include_directories: include_dirs,
    link_with: links
)

executable('udp_server', udp_server_src, 
    include_directories: include_dirs,
    link_with: links
)

executable('tcp_client', tcp_client_src, 
    include_directories: include_dirs,
    link_with: links
)

executable('tcp_server', tcp_server_src, 
    include_directories: include_dirs,
    link_with: links
)

