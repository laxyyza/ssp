#include "uft_client.h"

static void 
client_send(uft_client_t* client)
{
	ssp_packet_t* packet;

	packet = ssp_io_serialize(&client->io);
	if (packet == NULL)
		return;

	if (sendto(client->sockfd, packet->buf, packet->size, 0, (struct sockaddr*)&client->server_addr, client->addr_len) == -1)
		perror("sendto");

	ssp_packet_free(packet);
}

static void 
client_connect(uft_client_t* client, const char* address)
{
	printf("Connecting to %s:%u... ", address, PORT);
	fflush(stdout);

    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_addr.s_addr = inet_addr(address);
    client->server_addr.sin_port = htons(PORT);
    client->addr_len = sizeof(struct sockaddr_in);

	ssp_io_push_ref(&client->io, UFT_CONNECT, 0, NULL);

	client_send(client);
}

static void 
client_session(const ssp_segment_t* segment, uft_client_t* client, _SSP_UNUSED void* source_data)
{
	const uft_session_t* session = (const void*)segment->data;

	client->io.session_id = session->session_id;
	client->io.tx.flags |= SSP_SESSION_BIT;

	ssp_io_push_ref(&client->io, UFT_SESSION, 0, NULL);

	client->connected = true;
	printf("Connected!\n");
}

static bool
client_verify(u32 session_id, uft_client_t* client, _SSP_UNUSED void* source_data, _SSP_UNUSED void* new_source, _SSP_UNUSED ssp_io_t** io)
{
	return session_id == client->io.session_id;
}

static void 
client_read(uft_client_t* client)
{
	u32 buf_size = 2048;
	void* buf = malloc(buf_size);
	i64 bytes_read;

	if ((bytes_read = recvfrom(client->sockfd, buf, buf_size, 0, NULL, NULL)) == -1)
	{
		perror("recvfrom");
		free(buf);
		exit(-1);
	}

	ssp_io_process_params_t params = {
		.buf = buf,
		.size = bytes_read,
		.io = &client->io,
		.peer_data = NULL,
	};
	ssp_io_process(&params);
}

static i32
client_init(uft_client_t* client, const char* address)
{
    if ((client->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

	ssp_io_ctx_init(&client->ssp_ctx, UFT_SSP_MAGIC, client);
	ssp_io_ctx_verify_callback(&client->ssp_ctx, (ssp_session_verify_callback_t)client_verify);
	ssp_io_init(&client->io, &client->ssp_ctx, SSP_IMPORTANT_BIT);

	ssp_io_ctx_register_dispatch(&client->ssp_ctx, UFT_SESSION, (ssp_segment_callback_t)client_session);

	client->connected = false;
	client_connect(client, address);

    return 0;
}

static i32 
client_run(uft_client_t* client)
{
	struct pollfd pfd = {
		.fd = client->sockfd,
		.events = POLLIN
	};
	i32 ret;

	while (1)
	{
		if ((ret = poll(&pfd, 1, 1000)) == -1)
		{
			perror("poll");
			return -1;
		}

		if (ret == 1)
		{
			client_read(client);
			client_send(client);
		}
		else if (ret == 0 && client->connected == false)
		{
			printf("FAILED (timed out).\n");
			return -1;
		}
	}

	return 0;
}

i32 
main(i32 argc, const char** argv)
{
	i32 ret;
	if (argc <= 1)
		return -1;

	uft_client_t client = {0};
	if (client_init(&client, argv[1]) == -1)
		return -1;

	ret = client_run(&client);

	return ret;
}
