tcp_client_src = files('tcp_client.c')
tcp_server_src = files('tcp_server.c')
udp_client_src = files('udp_client.c')

executable('tcp_client', tcp_client_src, include_directories: ssp_include,
    link_with: [
        libssp
    ]
)

executable('udp_client', udp_client_src, include_directories: ssp_include,
    link_with: [
        libssp
    ]
)

executable('tcp_server', tcp_server_src, 
    include_directories: [
        ssp_include, 
        ght_include
    ],
    link_with: [
        libssp,
        libght
    ]
)
