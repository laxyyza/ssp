#include "uft_server.h"
#include <sys/random.h>

static client_t*
new_client(uft_server_t* server, const uft_addr_t* addr)
{
	client_t* client = calloc(1, sizeof(client_t));
	memcpy(&client->addr, addr, sizeof(uft_addr_t));
	getrandom(&client->session_id, sizeof(u32), 0);

	ssp_io_init(&client->io, &server->ssp_ctx, SSP_IMPORTANT_BIT);
	ssp_io_required_flags(&client->io, UFT_SSP_FLAGS);
	client->io.rx.acks.min = 0;
	client->io.rx.acks.max = 0;
	client->io.rx.window.next_seq++;
	client->io.session_id = client->session_id;

    ght_insert(&server->clients, client->session_id, client);

	return client;
}

static void 
server_accept(_SSP_UNUSED const ssp_segment_t* segment, uft_server_t* server, const uft_addr_t* addr)
{
	client_t* client = new_client(server, addr);
	uft_session_t* session = mmframes_alloc(&server->mmf, sizeof(uft_session_t));
	session->session_id = client->session_id;

	ssp_io_push_ref(&client->io, UFT_SESSION, sizeof(uft_session_t), session);
}

static void 
uft_session(_SSP_UNUSED const ssp_segment_t* segment, _SSP_UNUSED uft_server_t* server, client_t* client)
{
	client->connected = true;
	client->io.tx.flags |= UFT_SSP_FLAGS;
	printf("Client (%s:%u) connected.\n", client->addr.ip, client->addr.port);
}

static bool
uft_server_verify(u32 session_id, uft_server_t* server, const uft_addr_t* addr, void** new_source, ssp_io_t** io)
{
	client_t* client;

	client = ght_get(&server->clients, session_id);
	if (client == NULL)
	{
		printf("No client with session ID: %u\n", session_id);
		return false;
	}

	// TODO: Send reconnect command to client.
	if (strncmp(client->addr.ip, addr->ip, INET_ADDRSTRLEN))
	{
		printf("Client (%u) packet IP address is different: %s -> %s. Discarding packet.\n", 
			client->session_id, client->addr.ip, addr->ip);
		return false;
	}

	if (client->addr.port != addr->port)
	{
		printf("Client's (%u) packet PORT is different: %u -> %u. Discarding packet.\n", 
			client->session_id, client->addr.port, addr->port);
		return false;
	}

	*new_source = client;
	*io = &client->io;

	return true;
}

static void 
uft_upload(const ssp_segment_t* segment, uft_server_t* server, client_t* client)
{
	const uft_upload_t* upload = (const void*)segment->data;

	printf("path: %s\n", upload->path);

	i32 fd = file_exists(upload->path, true);
	if (fd == -1)
	{
		uft_error_t* error = mmframes_zalloc(&server->mmf, sizeof(uft_error_t));
		error->code = errno;
		snprintf(error->msg, ERROR_MSG_LEN, "'%s': %s", upload->path, strerror(error->code));

		ssp_io_push_ref(&client->io, UFT_ERROR, sizeof(uft_error_t), error);
	}
	else
	{
		ssp_io_push_ref(&client->io, UFT_OK, 0, NULL);
		client->file_fd = fd;
	}
}

static void 
uft_file_data(const ssp_segment_t* segment, _SSP_UNUSED uft_server_t* server, client_t* client)
{
	if (write(client->file_fd, segment->data, segment->size) == -1)
	{
		perror("write");
	}
}

static i32 
uft_server_init(uft_server_t* server)
{
    if ((server->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

    server->addr.sin_family = AF_INET;
    server->addr.sin_addr.s_addr = INADDR_ANY;
    server->addr.sin_port = htons(PORT);
    server->addr_len = sizeof(struct sockaddr_in);

    i32 opt = 1;
    if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(i32)) == -1)
    {
        perror("setsockopt");
        return -1;
    }

    if (bind(server->sockfd, (struct sockaddr*)&server->addr, server->addr_len) == -1)
    {
        perror("bind");
        return -1;
    }

	mmframes_init(&server->mmf);
	ght_init(&server->clients, 10, free);

	ssp_io_ctx_init(&server->ssp_ctx, UFT_SSP_MAGIC, server);

	ssp_io_ctx_verify_callback(&server->ssp_ctx, (ssp_session_verify_callback_t)uft_server_verify);

	ssp_io_ctx_register_dispatch(&server->ssp_ctx, UFT_CONNECT, (ssp_segment_callback_t)server_accept);
	ssp_io_ctx_register_dispatch(&server->ssp_ctx, UFT_SESSION, (ssp_segment_callback_t)uft_session);
	ssp_io_ctx_register_dispatch(&server->ssp_ctx, UFT_UPLOAD, (ssp_segment_callback_t)uft_upload);
	ssp_io_ctx_register_dispatch(&server->ssp_ctx, UFT_FILE_DATA, (ssp_segment_callback_t)uft_file_data);

    return 0;
}

static const char* 
ssp_error_str(i32 error)
{
	switch (error)
	{
		case SSP_MORE:
			return "SSP_MORE";
		case SSP_BUFFERED:
			return "SSP_BUFFERED";
		case SSP_CALLBACK_NOT_ASSIGN:
			return "SSP_CALLBACK_NOT_ASSIGN";
		case SSP_SUCCESS:
			return "SSP_SUCCESS";
		case SSP_FAILED:
			return "SSP_FAILED";
		case SSP_INCOMPLETE:
			return "SSP_INCOMPLETE";
		case SSP_NOT_USED:
			return "SSP_NOT_USED";
		default:
			return "Unknown";
	}
}

static void
read_socket(uft_server_t* server)
{
    void* buf;
    i64 bytes_read;
	uft_addr_t client_addr = {
		.in_len = sizeof(struct sockaddr_in)
	};
	hr_time_t current_time;

	u32 buf_size = 2048;
    buf = mmframes_alloc(&server->mmf, buf_size);

    if ((bytes_read = recvfrom(server->sockfd, buf, buf_size, 0, (struct sockaddr*)&client_addr.in, &client_addr.in_len)) == -1)
    {
        perror("recvfrom");
        exit(-1);
    }
	nano_gettime(&current_time);

    inet_ntop(AF_INET, &client_addr.in.sin_addr, client_addr.ip, INET_ADDRSTRLEN);
	client_addr.port = ntohs(client_addr.in.sin_port);

	ssp_io_process_params_t params = {
		.buf = buf,
		.ctx = &server->ssp_ctx,
		.size = bytes_read,
		.peer_data = &client_addr,
		.io = NULL,
		.timestamp_s = nano_time_s(&current_time)
	};
	i32 ret = ssp_io_process(&params);
	printf("Recv %zu bytes from %s:%u - %s (%d)\n", 
		bytes_read, client_addr.ip, client_addr.port, ssp_error_str(ret), ret);
}

static void 
uft_flush_client(uft_server_t* server, client_t* client)
{
	ssp_packet_t* packet;

	packet = ssp_io_serialize(&client->io);
	if (packet == NULL)
		return;

	if (sendto(server->sockfd, packet->buf, packet->size, 0, (struct sockaddr*)&client->addr.in, client->addr.in_len) == -1)
		perror("sendto");

	ssp_packet_free(packet);
}

static void 
uft_flush_clients(uft_server_t* server)
{
	ght_t* clients = &server->clients;
	GHT_FOREACH(client_t* client, clients, {
		uft_flush_client(server, client);
	});
}

static void
uft_server_run(uft_server_t* server)
{
    i32 ret;
    struct pollfd pfd = {
        .fd = server->sockfd,
        .events = POLLIN
    };

    printf("Listening to port: %u\n", PORT);

    for (;;)
    {
        if ((ret = poll(&pfd, 1, -1)) == -1)
        {
            perror("poll");
            return;
        }

        read_socket(server);

		uft_flush_clients(server);
    }
}

i32
main(void)
{
    uft_server_t server = {0};

    if (uft_server_init(&server) == -1)
        return -1;
    uft_server_run(&server);

    return 0;
}
