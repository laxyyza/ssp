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
client_connect(uft_client_t* client)
{
	printf("Connecting to %s:%u... ", client->ip_address, PORT);
	fflush(stdout);

    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_addr.s_addr = inet_addr(client->ip_address);
    client->server_addr.sin_port = htons(PORT);
    client->addr_len = sizeof(struct sockaddr_in);

	ssp_io_push_ref(&client->io, UFT_CONNECT, 0, NULL);

	client_send(client);
}

static void 
client_send_upload(uft_client_t* client)
{
	u16 path_len = strnlen(client->server_path, MAX_FILE_PATH);
	u32 size = sizeof(uft_upload_t) + path_len + 1;
	uft_upload_t* upload = mmframes_zalloc(&client->mmf, size);
	upload->path_len = path_len;
	strncpy(upload->path, client->server_path, MAX_FILE_PATH);

	client->file_size = upload->file_size = file_size(client->local_fd);
	client->file_index = 0;

	ssp_io_push_ref(&client->io, UFT_UPLOAD, size, upload);
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
	if (client->upload)
		client_send_upload(client);
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

static bool 
has_ip_address(const char* str)
{
	return strchr(str, ':') != NULL;
}

static i32
client_argv(uft_client_t* client, i32 argc, char* const* argv)
{
	if (argc != 3)
		return -1;

	if (has_ip_address(argv[1]))
	{
		client->ip_address = strtok(argv[1], ":");
		client->server_path = strtok(NULL, "");
		client->local_path = argv[2];
		client->upload = false;
	}
	else if (has_ip_address(argv[2]))
	{
		client->ip_address = strtok(argv[2], ":");
		client->server_path = strtok(NULL, "");
		client->local_path = argv[1];
		client->upload = true;
	}
	else
	{
		fprintf(stderr, "One of the arguments must contain an IP address.\n");
		return -1;
	}

	return 0;
}

static void 
uft_error(const ssp_segment_t* segment, _SSP_UNUSED uft_client_t* client, _SSP_UNUSED void* source_data)
{
	const uft_error_t* error = (const void*)segment->data;
	fprintf(stderr, "SERVER ERROR: %s (%d)\n",
		error->msg, error->code);

	exit(-1);
}

static void 
do_upload(uft_client_t* client)
{
	if (client->busy_uploading == false)
		return;

	u32 size = FILE_CHUNK;
	if (client->file_index >= client->file_size)
		exit(0);

	i64 bytes_left = client->file_size - client->file_index;
	if (bytes_left < FILE_CHUNK)
		size = bytes_left;

	ssp_io_push_ref(&client->io, UFT_FILE_DATA, size, client->file_data + client->file_index);
	client->file_index += size;

	printf("%zu/%zu\n", client->file_index, client->file_size);
}

static void 
uft_ok(_SSP_UNUSED const ssp_segment_t* segment, uft_client_t* client, _SSP_UNUSED void* source_data)
{
	printf("Ok! %s...\n", (client->upload) ? "Uploading" : "Downloading");

	client->file_data = malloc(client->file_size);
	if (read(client->local_fd, client->file_data, client->file_size) == -1)
		perror("read");

	client->busy_uploading = true;
}

static i32
client_init(uft_client_t* client, i32 argc, char* const* argv)
{
	if (client_argv(client, argc, argv) == -1)
		return -1;

	if ((client->local_fd = file_exists(client->local_path, client->upload == false)) == -1)
		return -1;

    if ((client->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

	mmframes_init(&client->mmf);

	ssp_io_ctx_init(&client->ssp_ctx, UFT_SSP_MAGIC, client);
	ssp_io_ctx_verify_callback(&client->ssp_ctx, (ssp_session_verify_callback_t)client_verify);
	ssp_io_init(&client->io, &client->ssp_ctx, SSP_IMPORTANT_BIT);

	ssp_io_ctx_register_dispatch(&client->ssp_ctx, UFT_SESSION, (ssp_segment_callback_t)client_session);
	ssp_io_ctx_register_dispatch(&client->ssp_ctx, UFT_ERROR, (ssp_segment_callback_t)uft_error);
	ssp_io_ctx_register_dispatch(&client->ssp_ctx, UFT_OK, (ssp_segment_callback_t)uft_ok);

	client->connected = false;
	client_connect(client);

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
			do_upload(client);
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
main(i32 argc, char* const* argv)
{
	i32 ret;

	uft_client_t client = {0};
	if (client_init(&client, argc, argv) == -1)
		return -1;

	ret = client_run(&client);

	return ret;
}
