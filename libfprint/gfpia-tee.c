// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Talking to a Qualcomm Trusted Execution Environment application.
 *
 * Everything here was lifted unchanged from the program it was written and
 * proven in against a Xiaomi Pad 8 Pro,
 * qcomtee/qcomtee-qseecom.c: opening the qcomtee device,
 * reaching the QSEECom compatibility loader, reassembling a split MDT image,
 * and sending a modified command with its payload in a memory object. Only
 * the fingerprint protocol on top of it is new.
 */

#include "gfpia-tee.h"

#include <elf.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int report_errno(const char *what)
{
	int error = errno;

	fprintf(stderr, "%s: %s\n", what, strerror(error));
	return -error;
}

static bool size_add_overflow(size_t a, size_t b, size_t *result)
{
	if (a > SIZE_MAX - b)
		return true;

	*result = a + b;
	return false;
}

uint32_t read_le32(const uint8_t *data)
{
	return (uint32_t)data[0] | (uint32_t)data[1] << 8 |
	       (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
}

void write_le32(uint8_t *data, uint32_t value)
{
	data[0] = (uint8_t)value;
	data[1] = (uint8_t)(value >> 8);
	data[2] = (uint8_t)(value >> 16);
	data[3] = (uint8_t)(value >> 24);
}

uint16_t read_le16(const uint8_t *data)
{
	return (uint16_t)data[0] | (uint16_t)data[1] << 8;
}

uint64_t read_le64(const uint8_t *data)
{
	return (uint64_t)read_le32(data) |
	       (uint64_t)read_le32(data + sizeof(uint32_t)) << 32;
}

void write_le64(uint8_t *data, uint64_t value)
{
	write_le32(data, (uint32_t)value);
	write_le32(data + sizeof(uint32_t), (uint32_t)(value >> 32));
}

void secure_clear(void *data, size_t size)
{
	volatile uint8_t *byte = data;

	if (!data)
		return;
	while (size--)
		*byte++ = 0;
}

void secure_free_blob(struct blob *blob)
{
	if (!blob)
		return;
	if (blob->data) {
		secure_clear(blob->data, blob->size);
		free(blob->data);
	}
	blob->data = NULL;
	blob->size = 0;
}

int object_invoke(int fd, struct qtee_object object, uint32_t op,
			 struct tee_ioctl_param *params, uint32_t num_params,
			 uint32_t *secure_result)
{
	struct tee_ioctl_object_invoke_arg *arg;
	struct tee_ioctl_buf_data data;
	size_t params_size;
	size_t arg_size;
	int ret = 0;

	if (num_params > 64U)
		return -EINVAL;

	params_size = (size_t)num_params * sizeof(*params);
	if (size_add_overflow(sizeof(*arg), params_size, &arg_size))
		return -EOVERFLOW;

	arg = calloc(1, arg_size);
	if (!arg)
		return -ENOMEM;

	arg->id = object.id;
	arg->op = op;
	arg->num_params = num_params;
	if (num_params)
		memcpy(arg->params, params, params_size);

	data.buf_ptr = (uintptr_t)arg;
	data.buf_len = arg_size;
	if (ioctl(fd, TEE_IOC_OBJECT_INVOKE, &data) < 0) {
		ret = report_errno("TEE_IOC_OBJECT_INVOKE");
		goto out;
	}

	if (num_params)
		memcpy(params, arg->params, params_size);
	if (secure_result)
		*secure_result = arg->ret;

out:
	free(arg);
	return ret;
}

int object_release(int fd, struct qtee_object *object)
{
	uint32_t secure_result = 0;
	int ret;

	if (!object || object->id == TEE_OBJREF_NULL)
		return 0;

	ret = object_invoke(fd, *object, QCOMTEE_OBJECT_OP_RELEASE, NULL, 0,
			    &secure_result);
	object->id = TEE_OBJREF_NULL;
	object->flags = 0;
	if (ret)
		return ret;

	return secure_result ? -EREMOTEIO : 0;
}

int shared_memory_alloc(int tee_fd, size_t size,
			       struct qtee_shared_memory *memory)
{
	struct tee_ioctl_shm_alloc_data data = {
		.size = size,
	};
	int fd;

	if (!size || size > MAX_APP_IMAGE_SIZE)
		return -EINVAL;

	fd = ioctl(tee_fd, TEE_IOC_SHM_ALLOC, &data);
	if (fd < 0)
		return report_errno("TEE_IOC_SHM_ALLOC");
	if (data.id < 0 || data.size < size || data.size > SIZE_MAX) {
		close(fd);
		return -EPROTO;
	}

	memory->data = mmap(NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			    fd, 0);
	if (memory->data == MAP_FAILED) {
		int error = errno;

		memory->data = NULL;
		close(fd);
		errno = error;
		return report_errno("mmap TEE shared memory");
	}
	memory->size = data.size;
	memory->id = data.id;
	memory->fd = fd;

	return 0;
}

void shared_memory_release(struct qtee_shared_memory *memory)
{
	if (!memory)
		return;
	if (memory->data)
		munmap(memory->data, memory->size);
	if (memory->fd >= 0)
		close(memory->fd);
	memory->data = NULL;
	memory->size = 0;
	memory->id = -1;
	memory->fd = -1;
}

void secure_shared_memory_release(struct qtee_shared_memory *memory)
{
	if (memory && memory->data)
		secure_clear(memory->data, memory->size);
	shared_memory_release(memory);
}

int find_qcomtee_device(char *path, size_t path_size)
{
	struct tee_ioctl_version_data version;
	char candidate[32];
	unsigned int i;
	int fd;

	for (i = 0; i < 32U; i++) {
		if (snprintf(candidate, sizeof(candidate), "/dev/tee%u", i) >=
		    (int)sizeof(candidate))
			return -ENAMETOOLONG;

		fd = open(candidate, O_RDWR | O_CLOEXEC);
		if (fd < 0)
			continue;

		memset(&version, 0, sizeof(version));
		if (!ioctl(fd, TEE_IOC_VERSION, &version) &&
		    version.impl_id == TEE_IMPL_ID_QTEE &&
		    (version.gen_caps & TEE_GEN_CAP_OBJREF)) {
			if (snprintf(path, path_size, "%s", candidate) >=
			    (int)path_size) {
				close(fd);
				return -ENAMETOOLONG;
			}
			return fd;
		}

		close(fd);
	}

	return -ENODEV;
}

static struct tee_ioctl_param ubuf_input(const void *address, size_t size)
{
	struct tee_ioctl_param param = {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_INPUT,
		.a = (uintptr_t)address,
		.b = size,
	};

	return param;
}

static struct tee_ioctl_param ubuf_output(void *address, size_t size)
{
	struct tee_ioctl_param param = {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_OUTPUT,
		.a = (uintptr_t)address,
		.b = size,
	};

	return param;
}

static struct tee_ioctl_param objref_output(void)
{
	struct tee_ioctl_param param = {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_OBJREF_OUTPUT,
		.a = TEE_OBJREF_NULL,
	};

	return param;
}

static struct tee_ioctl_param objref_input(struct qtee_object object)
{
	struct tee_ioctl_param param = {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_OBJREF_INPUT,
		.a = object.id,
		.b = object.flags,
	};

	return param;
}

static int object_from_output(const struct tee_ioctl_param *param,
			      struct qtee_object *object)
{
	if (param->attr != TEE_IOCTL_PARAM_ATTR_TYPE_OBJREF_OUTPUT)
		return -EINVAL;
	if (param->a == TEE_OBJREF_NULL)
		return -ENODEV;
	if (!(param->b & QCOMTEE_OBJREF_FLAG_TEE))
		return -EPROTO;

	object->id = param->a;
	object->flags = param->b;
	return 0;
}

int get_client_env(int fd, struct qtee_object *client_env)
{
	/* CBOR: { 1: 1000, 3: "UefiSmcInvoke\0" }. */
	static const uint8_t credentials[] = {
		0xa2, 0x01, 0x19, 0x03, 0xe8, 0x03, 0x6e,
		'U', 'e', 'f', 'i', 'S', 'm', 'c', 'I', 'n', 'v', 'o', 'k', 'e', 0x00,
	};
	const struct qtee_object root = {
		.id = TEE_OBJREF_NULL,
	};
	struct tee_ioctl_param params[] = {
		ubuf_input(credentials, sizeof(credentials)),
		objref_output(),
	};
	uint32_t secure_result = 0;
	int ret;

	ret = object_invoke(fd, root, CLIENT_ENV_OP_REGISTER_LEGACY, params,
			    ARRAY_SIZE(params), &secure_result);
	if (ret)
		return ret;
	if (secure_result) {
		fprintf(stderr, "registerLegacy failed in QTEE: %" PRIu32 "\n",
			secure_result);
		return -EACCES;
	}

	return object_from_output(&params[1], client_env);
}

int client_env_open(int fd, struct qtee_object client_env, uint32_t uid,
			   struct qtee_object *service)
{
	struct tee_ioctl_param params[] = {
		ubuf_input(&uid, sizeof(uid)),
		objref_output(),
	};
	uint32_t secure_result = 0;
	int ret;

	ret = object_invoke(fd, client_env, CLIENT_ENV_OP_OPEN, params,
			    ARRAY_SIZE(params), &secure_result);
	if (ret)
		return ret;
	if (secure_result) {
		fprintf(stderr, "ClientEnv.open(UID %" PRIu32
			") failed in QTEE: %" PRIu32 "\n", uid, secure_result);
		return -ENOENT;
	}

	return object_from_output(&params[1], service);
}

static int app_loader_lookup(int fd, struct qtee_object loader,
			     const char *app_name,
			     struct qtee_object *controller,
			     uint32_t *secure_result)
{
	struct tee_ioctl_param params[] = {
		ubuf_input(app_name, strlen(app_name)),
		objref_output(),
	};
	int ret;

	*secure_result = 0;
	ret = object_invoke(fd, loader, APP_LOADER_OP_LOOKUP_TA, params,
			    ARRAY_SIZE(params), secure_result);
	if (ret || *secure_result)
		return ret;

	return object_from_output(&params[1], controller);
}

static int app_loader_load(int fd, struct qtee_object loader,
				   const char *app_name, const struct blob *image,
				   struct qtee_object *controller)
{
	char dist_name[MAX_DIST_NAME_SIZE] = { 0 };
	struct tee_ioctl_param params[] = {
		ubuf_input(image->data, image->size),
		ubuf_input(app_name, strlen(app_name)),
		ubuf_output(dist_name, sizeof(dist_name)),
		objref_output(),
	};
	uint32_t secure_result = 0;
	int ret;

	ret = object_invoke(fd, loader, APP_LOADER_OP_LOAD_FROM_BUFFER, params,
			    ARRAY_SIZE(params), &secure_result);
	if (ret)
		return ret;
	if (secure_result) {
		fprintf(stderr, "loadFromBuffer failed in QTEE: %" PRIu32 "\n",
			secure_result);
		return -EKEYREJECTED;
	}
	if (params[2].b > sizeof(dist_name))
		return -EPROTO;

	fprintf(stdout, "QTEE loaded %s as %.*s\n", app_name,
		(int)params[2].b, dist_name);
	return object_from_output(&params[3], controller);
}

static int app_loader_load_region(int fd, struct qtee_object loader,
				  const char *app_name, const struct blob *image,
				  struct qtee_object *controller)
{
	struct qtee_shared_memory region = {
		.id = -1,
		.fd = -1,
	};
	struct tee_ioctl_param params[3];
	struct qtee_object region_object;
	uint32_t secure_result = 0;
	int ret;

	ret = shared_memory_alloc(fd, image->size, &region);
	if (ret)
		return ret;
	memset(region.data, 0, region.size);
	memcpy(region.data, image->data, image->size);

	region_object.id = (uint64_t)region.id;
	region_object.flags = QCOMTEE_OBJREF_FLAG_MEM;
	params[0] = ubuf_input(app_name, strlen(app_name));
	params[1] = objref_input(region_object);
	params[2] = objref_output();

	ret = object_invoke(fd, loader, APP_LOADER_OP_LOAD_FROM_REGION, params,
			    ARRAY_SIZE(params), &secure_result);
	if (ret)
		goto out;
	if (secure_result) {
		fprintf(stderr, "loadFromRegion failed in QTEE: %" PRIu32 "\n",
			secure_result);
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = object_from_output(&params[2], controller);
	if (!ret)
		fprintf(stdout, "QTEE loaded %s from a %zu-byte memory region\n",
			app_name, image->size);

out:
	shared_memory_release(&region);
	return ret;
}

int read_file(const char *path, size_t maximum, struct blob *blob)
{
	struct stat st;
	ssize_t count;
	size_t offset = 0;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return report_errno(path);
	if (fstat(fd, &st) < 0) {
		close(fd);
		return report_errno("fstat");
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    (uintmax_t)st.st_size > maximum) {
		close(fd);
		return -EFBIG;
	}

	blob->size = (size_t)st.st_size;
	blob->data = malloc(blob->size);
	if (!blob->data) {
		close(fd);
		return -ENOMEM;
	}

	while (offset < blob->size) {
		count = read(fd, blob->data + offset, blob->size - offset);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			free(blob->data);
			blob->data = NULL;
			close(fd);
			return report_errno(path);
		}
		if (!count) {
			free(blob->data);
			blob->data = NULL;
			close(fd);
			return -EIO;
		}
		offset += (size_t)count;
	}

	close(fd);
	return 0;
}

static int elf_segment_offsets(const struct blob *header, uint64_t **offsets,
			       size_t *num_offsets)
{
	const unsigned char *ident;
	uint64_t *table;
	size_t ph_end;
	size_t i;

	if (header->size < EI_NIDENT)
		return -ENOEXEC;
	ident = header->data;
	if (memcmp(ident, ELFMAG, SELFMAG) || ident[EI_DATA] != ELFDATA2LSB)
		return -ENOEXEC;

	if (ident[EI_CLASS] == ELFCLASS64) {
		Elf64_Ehdr ehdr;

		if (header->size < sizeof(ehdr))
			return -ENOEXEC;
		memcpy(&ehdr, header->data, sizeof(ehdr));
		if (!ehdr.e_phnum || ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
		    ehdr.e_phoff > SIZE_MAX)
			return -ENOEXEC;
		if (size_add_overflow((size_t)ehdr.e_phoff,
				      (size_t)ehdr.e_phnum * sizeof(Elf64_Phdr),
				      &ph_end) || ph_end > header->size)
			return -ENOEXEC;

		table = calloc(ehdr.e_phnum, sizeof(*table));
		if (!table)
			return -ENOMEM;
		for (i = 1; i < ehdr.e_phnum; i++) {
			Elf64_Phdr phdr;

			memcpy(&phdr, header->data + ehdr.e_phoff +
			       i * sizeof(phdr), sizeof(phdr));
			table[i] = phdr.p_offset;
		}
		*num_offsets = ehdr.e_phnum;
	} else if (ident[EI_CLASS] == ELFCLASS32) {
		Elf32_Ehdr ehdr;

		if (header->size < sizeof(ehdr))
			return -ENOEXEC;
		memcpy(&ehdr, header->data, sizeof(ehdr));
		if (!ehdr.e_phnum || ehdr.e_phentsize != sizeof(Elf32_Phdr))
			return -ENOEXEC;
		if (size_add_overflow((size_t)ehdr.e_phoff,
				      (size_t)ehdr.e_phnum * sizeof(Elf32_Phdr),
				      &ph_end) || ph_end > header->size)
			return -ENOEXEC;

		table = calloc(ehdr.e_phnum, sizeof(*table));
		if (!table)
			return -ENOMEM;
		for (i = 1; i < ehdr.e_phnum; i++) {
			Elf32_Phdr phdr;

			memcpy(&phdr, header->data + ehdr.e_phoff +
			       i * sizeof(phdr), sizeof(phdr));
			table[i] = phdr.p_offset;
		}
		*num_offsets = ehdr.e_phnum;
	} else {
		return -ENOEXEC;
	}

	*offsets = table;
	return 0;
}

static int split_path(char *path, size_t path_size, const char *directory,
		      const char *app_name, size_t index)
{
	int count;

	count = snprintf(path, path_size, "%s/%s.b%02zu", directory,
			 app_name, index);
	if (count < 0 || (size_t)count >= path_size)
		return -ENAMETOOLONG;

	return 0;
}

static int load_split_image(const char *directory, const char *app_name,
			    struct blob *image)
{
	struct blob part = { 0 };
	struct blob first = { 0 };
	uint64_t *offsets = NULL;
	char path[PATH_MAX];
	size_t num_offsets = 0;
	size_t total_size;
	size_t end;
	size_t i;
	int ret;

	ret = split_path(path, sizeof(path), directory, app_name, 0);
	if (ret)
		return ret;
	ret = read_file(path, MAX_APP_IMAGE_SIZE, &first);
	if (ret)
		return ret;

	ret = elf_segment_offsets(&first, &offsets, &num_offsets);
	if (ret)
		goto out;

	total_size = first.size;
	for (i = 1; i < num_offsets; i++) {
		ret = split_path(path, sizeof(path), directory, app_name, i);
		if (ret)
			goto out;
		ret = read_file(path, MAX_APP_IMAGE_SIZE, &part);
		if (ret)
			goto out;
		if (offsets[i] > SIZE_MAX ||
		    size_add_overflow((size_t)offsets[i], part.size, &end) ||
		    end > MAX_APP_IMAGE_SIZE) {
			ret = -EFBIG;
			goto out;
		}
		if (end > total_size)
			total_size = end;
		free(part.data);
		part.data = NULL;
	}

	image->data = calloc(1, total_size);
	if (!image->data) {
		ret = -ENOMEM;
		goto out;
	}
	image->size = total_size;
	memcpy(image->data, first.data, first.size);

	for (i = 1; i < num_offsets; i++) {
		ret = split_path(path, sizeof(path), directory, app_name, i);
		if (ret)
			goto out_image;
		ret = read_file(path, MAX_APP_IMAGE_SIZE, &part);
		if (ret)
			goto out_image;
		if (offsets[i] > SIZE_MAX ||
		    size_add_overflow((size_t)offsets[i], part.size, &end) ||
		    end > image->size) {
			ret = -EFBIG;
			goto out_image;
		}
		memcpy(image->data + offsets[i], part.data, part.size);
		free(part.data);
		part.data = NULL;
	}

	fprintf(stdout, "reconstructed %s from %zu split files (%zu bytes)\n",
		app_name, num_offsets, image->size);
	ret = 0;
	goto out;

out_image:
	free(image->data);
	image->data = NULL;
	image->size = 0;
out:
	free(part.data);
	free(first.data);
	free(offsets);
	return ret;
}

static int load_image_source(const char *source, const char *app_name,
			     struct blob *image)
{
	struct stat st;
	int ret;

	if (stat(source, &st) < 0)
		return report_errno(source);
	if (S_ISDIR(st.st_mode))
		return load_split_image(source, app_name, image);
	if (!S_ISREG(st.st_mode))
		return -EINVAL;

	ret = read_file(source, MAX_APP_IMAGE_SIZE, image);
	if (ret)
		return ret;
	if (image->size < EI_NIDENT || memcmp(image->data, ELFMAG, SELFMAG) ||
	    (image->data[EI_CLASS] != ELFCLASS32 &&
	     image->data[EI_CLASS] != ELFCLASS64)) {
		free(image->data);
		image->data = NULL;
		image->size = 0;
		return -ENOEXEC;
	}

	return 0;
}

/**
 * app_unload() - Ask QTEE to drop a loaded application.
 * @fd: open TEE device.
 * @controller: controller the loader handed back.
 *
 * Takes no arguments either way. Failure is worth reporting but never worth
 * failing the run over: the caller is on its way out.
 */
void app_unload(int fd, struct qtee_object controller)
{
	uint32_t secure_result = 0;
	int ret;

	if (controller.id == TEE_OBJREF_NULL)
		return;

	ret = object_invoke(fd, controller, QSEECOM_APP_CONTROLLER_OP_UNLOAD,
			    NULL, 0, &secure_result);
	if (ret || secure_result)
		fprintf(stderr, "could not unload the application: %d/%" PRIu32
			"\n", ret, secure_result);
	else
		fprintf(stdout, "application unloaded\n");
}

int start_app(int fd, struct qtee_object loader, const char *app_name,
		     const char *source, struct qtee_object *controller)
{
	struct blob image = { 0 };
	uint32_t secure_result = 0;
	int ret;

	ret = app_loader_lookup(fd, loader, app_name, controller,
				&secure_result);
	if (ret)
		return ret;
	if (!secure_result) {
		fprintf(stdout, "QTEE TA %s is already loaded\n", app_name);
		return 0;
	}
	/* Some SM8750 firmware exposes the loader but not lookupTA itself. */
	if (secure_result != APP_LOADER_ERROR_APP_NOT_LOADED &&
	    secure_result != QTEE_OBJECT_ERROR_INVALID) {
		fprintf(stderr, "lookupTA failed in QTEE: %" PRIu32 "\n",
			secure_result);
		return -EREMOTEIO;
	}
	if (secure_result == QTEE_OBJECT_ERROR_INVALID)
		fprintf(stdout,
			"QTEE firmware does not implement lookupTA; trying load\n");

	ret = load_image_source(source, app_name, &image);
	if (ret) {
		fprintf(stderr, "failed to prepare image for %s: %s\n", app_name,
			strerror(-ret));
		return ret;
	}
	if (image.size > MAX_INLINE_IMAGE_SIZE)
		ret = app_loader_load_region(fd, loader, app_name, &image,
					     controller);
	else
		ret = app_loader_load(fd, loader, app_name, &image, controller);
	free(image.data);
	return ret;
}

int send_request(int fd, struct qtee_object controller,
			const struct blob *request,
			const struct qtee_shared_memory *payload,
			size_t response_size, struct blob *request_output,
			struct blob *response)
{
	const struct qtee_object null_object = {
		.id = TEE_OBJREF_NULL,
	};
	struct qtee_object payload_object = null_object;
	const uint32_t payload_offsets[4] = { 0 };
	const uint32_t *offsets = NULL;
	size_t offsets_size = 0;
	uint32_t app_is_64bit = 1;
	uint8_t *response_in = NULL;
	struct tee_ioctl_param params[10];
	uint32_t secure_result = 0;
	size_t transport_size = 256;
	int ret;

	if (size_add_overflow(transport_size, request->size, &transport_size) ||
	    size_add_overflow(transport_size, request->size, &transport_size) ||
	    size_add_overflow(transport_size, response_size, &transport_size) ||
	    size_add_overflow(transport_size, response_size, &transport_size) ||
	    transport_size > MAX_QTEE_INBOUND_SIZE)
		return -EFBIG;

	/* Preserve allocation lengths so every partial-failure path clears all data. */
	request_output->size = request->size;
	response->size = response_size;
	request_output->data = calloc(1, request_output->size);
	response_in = calloc(1, response_size);
	response->data = calloc(1, response->size);
	if (!request_output->data || !response_in || !response->data) {
		ret = -ENOMEM;
		goto out;
	}

	if (payload) {
		if (request->size < sizeof(uint64_t)) {
			ret = -EINVAL;
			goto out;
		}
		payload_object.id = (uint64_t)payload->id;
		payload_object.flags = QCOMTEE_OBJREF_FLAG_MEM;
		offsets = payload_offsets;
		offsets_size = sizeof(payload_offsets);
	}

	/* QSEEComCompat.sendRequest: 4 IB, 2 OB, 4 IO, no OO. */
	params[0] = ubuf_input(request->data, request->size);
	params[1] = ubuf_input(response_in, response_size);
	params[2] = ubuf_input(offsets, offsets_size);
	params[3] = ubuf_input(&app_is_64bit, sizeof(app_is_64bit));
	params[4] = ubuf_output(request_output->data, request->size);
	params[5] = ubuf_output(response->data, response_size);
	params[6] = objref_input(payload_object);
	params[7] = objref_input(null_object);
	params[8] = objref_input(null_object);
	params[9] = objref_input(null_object);

	ret = object_invoke(fd, controller, QSEECOM_COMPAT_OP_SEND_REQUEST,
			    params, ARRAY_SIZE(params), &secure_result);
	if (ret)
		goto out;
	if (secure_result) {
		fprintf(stderr, "sendRequest failed in QTEE: %" PRIu32 "\n",
			secure_result);
		ret = -EREMOTEIO;
		goto out;
	}
	if (params[4].b > request->size || params[5].b > response_size) {
		ret = -EPROTO;
		goto out;
	}
	secure_clear(request_output->data + params[4].b,
		     request->size - params[4].b);
	secure_clear(response->data + params[5].b,
		     response_size - params[5].b);
	request_output->size = params[4].b;
	response->size = params[5].b;

out:
	if (ret) {
		secure_clear(request_output->data, request_output->size);
		free(request_output->data);
		request_output->data = NULL;
		request_output->size = 0;
		secure_clear(response->data, response->size);
		free(response->data);
		response->data = NULL;
		response->size = 0;
	}
	secure_clear(response_in, response_size);
	free(response_in);
	return ret;
}
