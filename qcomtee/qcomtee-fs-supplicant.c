// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/tee.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define QCOMTEE_OBJREF_FLAG_TEE (1U << 0)
#define QCOMTEE_OBJREF_FLAG_USER (1U << 1)
#define QCOMTEE_OBJREF_FLAG_MEM (1U << 2)
#define QCOMTEE_OBJECT_OP_RELEASE UINT32_C(0xffff)

#define ROOT_OP_REGISTER_AS_CLIENT UINT32_C(2)
#define CLIENT_ENV_OP_OPEN UINT32_C(0)
#define REGISTER_LISTENER_OP_REGISTER UINT32_C(0)
#define REGISTER_LISTENER_UID UINT32_C(87)

#define QCOMTEE_OK UINT32_C(0)
#define QCOMTEE_ERROR UINT32_C(1)
#define QCOMTEE_ERROR_INVALID UINT32_C(2)

#define CREDENTIALS_OBJECT_ID UINT64_C(1)
#define FS_OBJECT_ID UINT64_C(2)
#define GPFS_OBJECT_ID UINT64_C(3)

#define FS_LISTENER_ID UINT32_C(10)
#define FS_BUFFER_SIZE (20U * 1024U)
#define FS_PATH_SIZE 256U
#define FS_DATA_SIZE 20000U
#define FS_READ_RESPONSE_SIZE 20008U

#define FS_OP_OPEN UINT32_C(0x202)
#define FS_OP_READ UINT32_C(0x207)
#define FS_OP_WRITE UINT32_C(0x208)
#define FS_OP_CLOSE UINT32_C(0x209)
#define FS_OP_LSEEK UINT32_C(0x20a)
#define FS_OP_UNLINK UINT32_C(0x20c)
#define FS_OP_FSYNC UINT32_C(0x216)
#define FS_OP_RENAME UINT32_C(0x217)
#define FS_OP_GET_ERRNO UINT32_C(0x21c)

#define GPFS_LISTENER_ID UINT32_C(0x7000)
#define GPFS_BUFFER_SIZE (504U * 1024U)
/*
 * A write puts its data at offset 272 of the shared buffer, so the most it can
 * carry is whatever is left after that header. The TA uses every byte of it:
 * a Goodix template comes over as exactly 515824 bytes, which is this buffer
 * minus the header, and a smaller round figure here refuses the one write that
 * matters.
 */
#define GPFS_WRITE_HEADER_SIZE 272U
#define GPFS_READ_HEADER_SIZE 12U
#define GPFS_DATA_SIZE (GPFS_BUFFER_SIZE - GPFS_WRITE_HEADER_SIZE)
#define GPFS_READ_RESPONSE_SIZE (GPFS_READ_HEADER_SIZE + GPFS_DATA_SIZE)
#define GPFS_VERSION_OP UINT32_C(12)

#define MAX_FS_HANDLES 64U
#define MAX_WORKERS 4U
#define MAX_CALLBACK_PARAMS 10U
#define CALLBACK_INPUT_SIZE 4096U

struct qtee_object {
	uint64_t id;
	uint64_t flags;
};

struct qtee_shared_memory {
	uint8_t *data;
	size_t size;
	int32_t id;
	int fd;
};

struct fs_handle {
	int fd;
	uint32_t generation;
	char path[FS_PATH_SIZE + 1U];
};

struct storage_backend {
	int root_fd;
	int last_errno;
	uint32_t temp_sequence;
	pthread_mutex_t lock;
	struct fs_handle handles[MAX_FS_HANDLES];
};

struct listener {
	uint32_t id;
	uint64_t object_id;
	struct qtee_shared_memory memory;
	pthread_mutex_t call_lock;
	struct storage_backend *storage;
};

struct supplicant {
	int tee_fd;
	struct qtee_object register_service;
	struct storage_backend storage;
	struct listener fs;
	struct listener gpfs;
	pthread_t workers[MAX_WORKERS];
	size_t workers_started;
	pthread_t main_thread;
	atomic_bool worker_failed;
	uint8_t credentials[32];
	size_t credentials_size;
};

struct parent_path {
	int fd;
	char leaf[NAME_MAX + 1U];
};

static volatile sig_atomic_t stop_requested;

static uint32_t get_le32(const void *pointer)
{
	const uint8_t *bytes = pointer;

	return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
	       (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static uint64_t get_le64(const void *pointer)
{
	const uint8_t *bytes = pointer;
	uint64_t value = 0;
	unsigned int i;

	for (i = 0; i < sizeof(value); i++)
		value |= (uint64_t)bytes[i] << (i * 8U);
	return value;
}

static int32_t get_le32s(const void *pointer)
{
	return (int32_t)get_le32(pointer);
}

static void put_le32(void *pointer, uint32_t value)
{
	uint8_t *bytes = pointer;

	bytes[0] = value;
	bytes[1] = value >> 8;
	bytes[2] = value >> 16;
	bytes[3] = value >> 24;
}

static void put_le64(void *pointer, uint64_t value)
{
	uint8_t *bytes = pointer;
	unsigned int i;

	for (i = 0; i < sizeof(value); i++)
		bytes[i] = value >> (i * 8U);
}

static int report_errno(const char *what)
{
	int error = errno;

	fprintf(stderr, "%s: %s\n", what, strerror(error));
	return -error;
}

static void handle_stop(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static void handle_wakeup(int signal_number)
{
	(void)signal_number;
}

static int decode_path(const uint8_t field[FS_PATH_SIZE],
		       char relative[FS_PATH_SIZE + 1U])
{
	const uint8_t *terminator;
	size_t component_start;
	size_t input_start = 0;
	size_t length;
	size_t i;

	terminator = memchr(field, '\0', FS_PATH_SIZE);
	if (!terminator)
		return EINVAL;
	length = (size_t)(terminator - field);
	if (!length)
		return EINVAL;

	if (field[0] == '/') {
		input_start = 1U;
		if (length == 1U)
			return EINVAL;
	}
	if (length - input_start > FS_PATH_SIZE)
		return ENAMETOOLONG;

	memcpy(relative, field + input_start, length - input_start);
	relative[length - input_start] = '\0';
	length -= input_start;
	if (!length || relative[length - 1U] == '/')
		return EINVAL;

	component_start = 0;
	for (i = 0; i <= length; i++) {
		size_t component_length;

		if (relative[i] != '/' && relative[i] != '\0')
			continue;
		component_length = i - component_start;
		if (!component_length || component_length > NAME_MAX)
			return component_length ? ENAMETOOLONG : EINVAL;
		if ((component_length == 1U &&
		     relative[component_start] == '.') ||
		    (component_length == 2U &&
		     relative[component_start] == '.' &&
		     relative[component_start + 1U] == '.'))
			return EINVAL;
		component_start = i + 1U;
	}

	return 0;
}

static int open_parent(struct storage_backend *storage, const char *relative,
		       bool create, struct parent_path *parent)
{
	char path[FS_PATH_SIZE + 1U];
	char *leaf;
	char *next;
	char *component;
	int current_fd;

	if (strlen(relative) > FS_PATH_SIZE)
		return ENAMETOOLONG;
	strcpy(path, relative);
	leaf = strrchr(path, '/');
	if (leaf) {
		*leaf++ = '\0';
	} else {
		leaf = path;
	}
	if (!*leaf || strlen(leaf) > NAME_MAX)
		return EINVAL;

	current_fd = dup(storage->root_fd);
	if (current_fd < 0)
		return errno;

	if (leaf != path) {
		component = path;
		while (component && *component) {
			bool created = false;
			int next_fd;

			next = strchr(component, '/');
			if (next)
				*next = '\0';
			next_fd = openat(current_fd, component,
					 O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
					 O_CLOEXEC);
			if (next_fd < 0 && errno == ENOENT && create) {
				if (!mkdirat(current_fd, component, 0700)) {
					created = true;
				} else if (errno != EEXIST) {
					int error = errno;

					close(current_fd);
					return error;
				}
				if (created && fsync(current_fd)) {
					int error = errno;

					close(current_fd);
					return error;
				}
				next_fd = openat(current_fd, component,
						 O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
						 O_CLOEXEC);
			}
			if (next_fd < 0) {
				int error = errno;

				close(current_fd);
				return error;
			}
			close(current_fd);
			current_fd = next_fd;
			component = next ? next + 1U : NULL;
		}
	}

	parent->fd = current_fd;
	strcpy(parent->leaf, leaf);
	return 0;
}

static int open_regular_at(int parent_fd, const char *leaf, int flags,
			   mode_t mode)
{
	struct stat status;
	int fd;

	fd = openat(parent_fd, leaf,
		    flags | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, mode);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &status)) {
		int error = errno;

		close(fd);
		return -error;
	}
	if (!S_ISREG(status.st_mode)) {
		close(fd);
		return -EINVAL;
	}

	return fd;
}

static int check_destination(int parent_fd, const char *leaf)
{
	struct stat status;

	if (!fstatat(parent_fd, leaf, &status, AT_SYMLINK_NOFOLLOW))
		return S_ISREG(status.st_mode) ? 0 : EINVAL;
	return errno == ENOENT ? 0 : errno;
}

static int write_all(int fd, const uint8_t *data, size_t size)
{
	size_t done = 0;

	while (done < size) {
		ssize_t count = write(fd, data + done, size - done);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			return errno;
		}
		if (!count)
			return EIO;
		done += (size_t)count;
	}

	return 0;
}

static int pwrite_all(int fd, const uint8_t *data, size_t size, off_t offset)
{
	size_t done = 0;

	while (done < size) {
		ssize_t count = pwrite(fd, data + done, size - done,
				       offset + (off_t)done);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			return errno;
		}
		if (!count)
			return EIO;
		done += (size_t)count;
	}

	return 0;
}

static int create_temp(struct storage_backend *storage, int parent_fd,
		       char name[64])
{
	unsigned int attempt;

	for (attempt = 0; attempt < 100U; attempt++) {
		int count;
		int fd;

		storage->temp_sequence++;
		count = snprintf(name, 64, ".qtee-tmp-%ld-%" PRIu32,
				 (long)getpid(), storage->temp_sequence);
		if (count < 0 || count >= 64)
			return -ENAMETOOLONG;
		fd = openat(parent_fd, name,
			    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
			    0600);
		if (fd >= 0)
			return fd;
		if (errno != EEXIST)
			return -errno;
	}

	return -EEXIST;
}

static int atomic_replace(struct storage_backend *storage, int parent_fd,
			  const char *leaf, const uint8_t *data, size_t size)
{
	char temporary[64];
	int error;
	int fd;

	error = check_destination(parent_fd, leaf);
	if (error)
		return error;
	fd = create_temp(storage, parent_fd, temporary);
	if (fd < 0)
		return -fd;

	error = write_all(fd, data, size);
	if (!error && fsync(fd))
		error = errno;
	if (close(fd) && !error)
		error = errno;
	if (!error && renameat(parent_fd, temporary, parent_fd, leaf))
		error = errno;
	if (!error && fsync(parent_fd))
		error = errno;
	if (error)
		unlinkat(parent_fd, temporary, 0);

	return error;
}

static int atomic_backup(struct storage_backend *storage, int parent_fd,
			 const char *leaf)
{
	char backup[NAME_MAX + 1U];
	char temporary[64];
	uint8_t buffer[16384];
	struct stat status;
	int destination = -1;
	int error = 0;
	int source;
	int count;

	count = snprintf(backup, sizeof(backup), "%s.bak", leaf);
	if (count < 0 || (size_t)count >= sizeof(backup))
		return ENAMETOOLONG;
	source = open_regular_at(parent_fd, leaf, O_RDONLY, 0);
	if (source == -ENOENT)
		return 0;
	if (source < 0)
		return -source;
	if (fstat(source, &status)) {
		error = errno;
		goto out;
	}
	error = check_destination(parent_fd, backup);
	if (error)
		goto out;
	destination = create_temp(storage, parent_fd, temporary);
	if (destination < 0) {
		error = -destination;
		destination = -1;
		goto out;
	}

	while (1) {
		ssize_t read_count = read(source, buffer, sizeof(buffer));

		if (read_count < 0) {
			if (errno == EINTR)
				continue;
			error = errno;
			break;
		}
		if (!read_count)
			break;
		error = write_all(destination, buffer, (size_t)read_count);
		if (error)
			break;
	}
	if (!error && fsync(destination))
		error = errno;
	if (close(destination) && !error)
		error = errno;
	destination = -1;
	if (!error && renameat(parent_fd, temporary, parent_fd, backup))
		error = errno;
	if (!error && fsync(parent_fd))
		error = errno;
	if (error)
		unlinkat(parent_fd, temporary, 0);

out:
	if (destination >= 0)
		close(destination);
	close(source);
	return error;
}

static int handle_allocate(struct storage_backend *storage, int fd,
			   const char *path)
{
	unsigned int i;

	for (i = 0; i < MAX_FS_HANDLES; i++) {
		struct fs_handle *handle = &storage->handles[i];
		uint32_t value;

		if (handle->fd >= 0)
			continue;
		handle->generation = (handle->generation + 1U) & 0x003fffffU;
		if (!handle->generation)
			handle->generation = 1U;
		handle->fd = fd;
		strcpy(handle->path, path);
		value = UINT32_C(0x40000000) | handle->generation << 6 | i;
		return (int)value;
	}

	return -1;
}

static struct fs_handle *handle_lookup(struct storage_backend *storage,
				       int value)
{
	uint32_t encoded = (uint32_t)value;
	uint32_t generation;
	unsigned int index;

	if ((encoded & UINT32_C(0xc0000000)) != UINT32_C(0x40000000))
		return NULL;
	index = encoded & 0x3fU;
	generation = (encoded >> 6) & 0x003fffffU;
	if (index >= MAX_FS_HANDLES || storage->handles[index].fd < 0 ||
	    storage->handles[index].generation != generation)
		return NULL;

	return &storage->handles[index];
}

static void fs_reply(uint8_t *buffer, uint32_t operation, int32_t result)
{
	put_le32(buffer, operation);
	put_le32(buffer + 4U, (uint32_t)result);
}

static void fs_failure(struct storage_backend *storage, uint8_t *buffer,
		       uint32_t operation, int error)
{
	storage->last_errno = error ? error : EIO;
	fs_reply(buffer, operation, -1);
}

static int fs_dispatch(struct storage_backend *storage, uint8_t *buffer,
		       size_t size)
{
	char path[FS_PATH_SIZE + 1U];
	char second_path[FS_PATH_SIZE + 1U];
	struct parent_path parent = { .fd = -1 };
	struct parent_path second_parent = { .fd = -1 };
	struct fs_handle *handle;
	uint32_t operation;
	int error = 0;

	if (size != FS_BUFFER_SIZE)
		return -EINVAL;
	operation = get_le32(buffer);
	pthread_mutex_lock(&storage->lock);

	switch (operation) {
	case FS_OP_OPEN: {
		const int allowed = O_ACCMODE | O_APPEND | O_CREAT | O_EXCL |
				    O_SYNC | O_TRUNC;
		int flags = get_le32s(buffer + 260U);
		int fd;
		int virtual_handle;

		error = decode_path(buffer + 4U, path);
		if (error || (flags & ~allowed)) {
			fs_failure(storage, buffer, operation,
				   error ? error : EINVAL);
			break;
		}
		error = open_parent(storage, path, flags & O_CREAT, &parent);
		if (error) {
			fs_failure(storage, buffer, operation, error);
			break;
		}
		fd = open_regular_at(parent.fd, parent.leaf, flags, 0600);
		if (fd < 0) {
			fs_failure(storage, buffer, operation, -fd);
			break;
		}
		if ((flags & O_CREAT) && fsync(parent.fd)) {
			error = errno;
			close(fd);
			fs_failure(storage, buffer, operation, error);
			break;
		}
		virtual_handle = handle_allocate(storage, fd, path);
		if (virtual_handle < 0) {
			close(fd);
			fs_failure(storage, buffer, operation, EMFILE);
			break;
		}
		fs_reply(buffer, operation, virtual_handle);
		break;
	}
	case FS_OP_READ: {
		uint32_t wanted = get_le32(buffer + 8U);
		ssize_t count;

		handle = handle_lookup(storage, get_le32s(buffer + 4U));
		if (!handle) {
			storage->last_errno = EBADF;
			put_le32(buffer, operation);
			put_le32(buffer + 20004U, UINT32_MAX);
			break;
		}
		if (wanted > FS_DATA_SIZE)
			wanted = FS_DATA_SIZE;
		memset(buffer + 4U, 0, FS_DATA_SIZE);
		do {
			count = read(handle->fd, buffer + 4U, wanted);
		} while (count < 0 && errno == EINTR);
		put_le32(buffer, operation);
		put_le32(buffer + 20004U, (uint32_t)(int32_t)count);
		if (count < 0)
			storage->last_errno = errno;
		break;
	}
	case FS_OP_WRITE: {
		uint32_t wanted = get_le32(buffer + 20008U);
		ssize_t count;

		handle = handle_lookup(storage, get_le32s(buffer + 4U));
		if (!handle) {
			fs_failure(storage, buffer, operation, EBADF);
			break;
		}
		if (wanted > FS_DATA_SIZE) {
			fs_failure(storage, buffer, operation, EINVAL);
			break;
		}
		do {
			count = write(handle->fd, buffer + 8U, wanted);
		} while (count < 0 && errno == EINTR);
		if (count < 0)
			fs_failure(storage, buffer, operation, errno);
		else
			fs_reply(buffer, operation, (int32_t)count);
		break;
	}
	case FS_OP_CLOSE:
		handle = handle_lookup(storage, get_le32s(buffer + 4U));
		if (!handle) {
			fs_failure(storage, buffer, operation, EBADF);
			break;
		}
		if (close(handle->fd)) {
			error = errno;
			handle->fd = -1;
			handle->path[0] = '\0';
			fs_failure(storage, buffer, operation, error);
		} else {
			handle->fd = -1;
			handle->path[0] = '\0';
			fs_reply(buffer, operation, 0);
		}
		break;
	case FS_OP_LSEEK: {
		off_t result;

		handle = handle_lookup(storage, get_le32s(buffer + 4U));
		if (!handle) {
			fs_failure(storage, buffer, operation, EBADF);
			break;
		}
		result = lseek(handle->fd, (off_t)get_le32s(buffer + 8U),
			       get_le32s(buffer + 12U));
		if (result < 0)
			fs_failure(storage, buffer, operation, errno);
		else if (result > INT32_MAX)
			fs_failure(storage, buffer, operation, EOVERFLOW);
		else
			fs_reply(buffer, operation, (int32_t)result);
		break;
	}
	case FS_OP_FSYNC:
		handle = handle_lookup(storage, get_le32s(buffer + 4U));
		if (!handle)
			fs_failure(storage, buffer, operation, EBADF);
		else if (fsync(handle->fd))
			fs_failure(storage, buffer, operation, errno);
		else
			fs_reply(buffer, operation, 0);
		break;
	case FS_OP_UNLINK:
		error = decode_path(buffer + 4U, path);
		if (!error)
			error = open_parent(storage, path, false, &parent);
		if (!error)
			error = check_destination(parent.fd, parent.leaf);
		if (!error && unlinkat(parent.fd, parent.leaf, 0))
			error = errno;
		if (!error && fsync(parent.fd))
			error = errno;
		if (error)
			fs_failure(storage, buffer, operation, error);
		else
			fs_reply(buffer, operation, 0);
		break;
	case FS_OP_RENAME:
		error = decode_path(buffer + 4U, path);
		if (!error)
			error = decode_path(buffer + 260U, second_path);
		if (!error)
			error = open_parent(storage, path, false, &parent);
		if (!error)
			error = open_parent(storage, second_path, true,
					    &second_parent);
		if (!error)
			error = check_destination(parent.fd, parent.leaf);
		if (!error)
			error = check_destination(second_parent.fd,
						  second_parent.leaf);
		if (!error && renameat(parent.fd, parent.leaf, second_parent.fd,
				       second_parent.leaf))
			error = errno;
		if (!error && fsync(second_parent.fd))
			error = errno;
		if (!error && fsync(parent.fd))
			error = errno;
		if (error)
			fs_failure(storage, buffer, operation, error);
		else
			fs_reply(buffer, operation, 0);
		break;
	case FS_OP_GET_ERRNO:
		fs_reply(buffer, operation, storage->last_errno);
		break;
	default:
		fs_failure(storage, buffer, operation, ENOSYS);
		break;
	}

	if (parent.fd >= 0)
		close(parent.fd);
	if (second_parent.fd >= 0)
		close(second_parent.fd);
	pthread_mutex_unlock(&storage->lock);
	return 0;
}

static int require_existing_regular(int parent_fd, const char *leaf)
{
	struct stat status;

	if (fstatat(parent_fd, leaf, &status, AT_SYMLINK_NOFOLLOW))
		return errno;
	return S_ISREG(status.st_mode) ? 0 : EINVAL;
}

static void gpfs_error_reply(uint8_t *buffer, uint32_t operation, int error,
			     bool include_count)
{
	put_le32(buffer, operation);
	put_le32(buffer + 4U, (uint32_t)(error ? error : EIO));
	if (include_count)
		put_le32(buffer + 8U, 0);
}

static int gpfs_read(struct storage_backend *storage, uint8_t *buffer,
		     uint32_t operation)
{
	char path[FS_PATH_SIZE + 1U];
	struct parent_path parent = { .fd = -1 };
	uint32_t wanted = get_le32(buffer + 264U);
	int32_t offset = get_le32s(buffer + 260U);
	size_t total = 0;
	int error;
	int fd = -1;

	error = decode_path(buffer + 4U, path);
	if (error || offset < 0) {
		error = error ? error : EINVAL;
		goto out;
	}
	if (wanted > GPFS_DATA_SIZE)
		wanted = GPFS_DATA_SIZE;
	error = open_parent(storage, path, false, &parent);
	if (error)
		goto out;
	fd = open_regular_at(parent.fd, parent.leaf, O_RDONLY, 0);
	if (fd < 0) {
		error = -fd;
		fd = -1;
		goto out;
	}

	memset(buffer, 0, GPFS_READ_RESPONSE_SIZE);
	while (total < wanted) {
		ssize_t count = pread(fd, buffer + 12U + total, wanted - total,
				      (off_t)offset + (off_t)total);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			error = errno;
			goto out;
		}
		if (!count)
			break;
		total += (size_t)count;
	}
	put_le32(buffer, operation);
	put_le32(buffer + 4U, 0);
	put_le32(buffer + 8U, (uint32_t)total);
	error = 0;

out:
	if (fd >= 0)
		close(fd);
	if (parent.fd >= 0)
		close(parent.fd);
	if (error)
		gpfs_error_reply(buffer, operation, error, true);
	return error;
}

static int gpfs_write(struct storage_backend *storage, uint8_t *buffer,
		      uint32_t operation)
{
	char path[FS_PATH_SIZE + 1U];
	struct parent_path parent = { .fd = -1 };
	uint32_t count = get_le32(buffer + 264U);
	uint32_t backup = get_le32(buffer + 268U);
	int32_t offset = get_le32s(buffer + 260U);
	int error;
	int fd = -1;

	error = decode_path(buffer + 4U, path);
	if (error || offset < 0 || count > GPFS_DATA_SIZE) {
		/*
		 * Say which of the three it was. A refused write is the last
		 * thing that stands between a finished enrolment and a stored
		 * template, and the reply carries no room to explain itself.
		 */
		fprintf(stderr,
			"gpfs write refused: path %s, offset %ld, count %lu (limit %lu)\n",
			error ? "undecodable" : path, (long)offset,
			(unsigned long)count, (unsigned long)GPFS_DATA_SIZE);
		fflush(stderr);
		error = error ? error : EINVAL;
		goto out;
	}
	error = open_parent(storage, path, true, &parent);
	if (error)
		goto out;
	if (backup) {
		error = atomic_backup(storage, parent.fd, parent.leaf);
		if (error)
			goto out;
	}

	if (!offset) {
		error = atomic_replace(storage, parent.fd, parent.leaf,
				       buffer + 272U, count);
	} else {
		fd = open_regular_at(parent.fd, parent.leaf, O_RDWR | O_CREAT,
				     0600);
		if (fd < 0) {
			error = -fd;
			fd = -1;
			goto out;
		}
		error = pwrite_all(fd, buffer + 272U, count, (off_t)offset);
		if (!error && fsync(fd))
			error = errno;
		if (!error && fsync(parent.fd))
			error = errno;
	}

out:
	if (fd >= 0)
		close(fd);
	if (parent.fd >= 0)
		close(parent.fd);
	if (error) {
		gpfs_error_reply(buffer, operation, error, true);
	} else {
		put_le32(buffer, operation);
		put_le32(buffer + 4U, 0);
		put_le32(buffer + 8U, count);
	}
	return error;
}

static int gpfs_remove(struct storage_backend *storage, uint8_t *buffer,
		       uint32_t operation)
{
	char path[FS_PATH_SIZE + 1U];
	struct parent_path parent = { .fd = -1 };
	int error;

	error = decode_path(buffer + 4U, path);
	if (!error)
		error = open_parent(storage, path, false, &parent);
	if (!error)
		error = require_existing_regular(parent.fd, parent.leaf);
	if (!error && unlinkat(parent.fd, parent.leaf, 0))
		error = errno;
	if (!error && fsync(parent.fd))
		error = errno;
	if (parent.fd >= 0)
		close(parent.fd);

	if (error)
		gpfs_error_reply(buffer, operation, error, false);
	else {
		put_le32(buffer, operation);
		put_le32(buffer + 4U, 0);
	}
	return error;
}

static int gpfs_rename(struct storage_backend *storage, uint8_t *buffer,
		       uint32_t operation)
{
	char old_path[FS_PATH_SIZE + 1U];
	char new_path[FS_PATH_SIZE + 1U];
	struct parent_path old_parent = { .fd = -1 };
	struct parent_path new_parent = { .fd = -1 };
	int error;

	error = decode_path(buffer + 4U, old_path);
	if (!error)
		error = decode_path(buffer + 260U, new_path);
	if (!error)
		error = open_parent(storage, old_path, false, &old_parent);
	if (!error)
		error = open_parent(storage, new_path, true, &new_parent);
	if (!error)
		error = require_existing_regular(old_parent.fd, old_parent.leaf);
	if (!error)
		error = check_destination(new_parent.fd, new_parent.leaf);
	if (!error && renameat(old_parent.fd, old_parent.leaf, new_parent.fd,
			       new_parent.leaf))
		error = errno;
	if (!error && fsync(new_parent.fd))
		error = errno;
	if (!error && old_parent.fd != new_parent.fd && fsync(old_parent.fd))
		error = errno;
	if (old_parent.fd >= 0)
		close(old_parent.fd);
	if (new_parent.fd >= 0)
		close(new_parent.fd);

	if (error)
		gpfs_error_reply(buffer, operation, error, false);
	else {
		put_le32(buffer, operation);
		put_le32(buffer + 4U, 0);
	}
	return error;
}

static int gpfs_dispatch(struct storage_backend *storage, uint8_t *buffer,
			 size_t size)
{
	uint32_t operation;
	int error = 0;

	if (size != GPFS_BUFFER_SIZE)
		return -EINVAL;
	operation = get_le32(buffer);
	pthread_mutex_lock(&storage->lock);
	if (operation == GPFS_VERSION_OP) {
		put_le32(buffer, operation);
		put_le32(buffer + 4U, 2);
		put_le32(buffer + 8U, 0);
	} else if (operation <= 11U) {
		switch (operation % 4U) {
		case 0:
			error = gpfs_read(storage, buffer, operation);
			break;
		case 1:
			error = gpfs_write(storage, buffer, operation);
			break;
		case 2:
			error = gpfs_remove(storage, buffer, operation);
			break;
		case 3:
			error = gpfs_rename(storage, buffer, operation);
			break;
		}
	} else {
		gpfs_error_reply(buffer, operation, EINVAL, false);
		error = EINVAL;
	}
	pthread_mutex_unlock(&storage->lock);

	fprintf(stdout, "listener 0x%x op 0x%x -> %s%s%s\n",
		GPFS_LISTENER_ID, operation, error ? "error " : "ok",
		error ? strerror(error) : "", error ? "" : "");
	fflush(stdout);
	/* Filesystem failures are protocol replies, not callback transport errors. */
	return 0;
}

static bool size_add_overflow(size_t first, size_t second, size_t *result)
{
	if (first > SIZE_MAX - second)
		return true;
	*result = first + second;
	return false;
}

static int object_invoke(int fd, struct qtee_object object, uint32_t operation,
			 struct tee_ioctl_param *params, uint32_t num_params,
			 uint32_t *secure_result)
{
	struct tee_ioctl_object_invoke_arg *argument;
	struct tee_ioctl_buf_data data;
	size_t params_size;
	size_t argument_size;
	int error = 0;

	if (num_params > 64U)
		return -EINVAL;
	params_size = (size_t)num_params * sizeof(*params);
	if (size_add_overflow(sizeof(*argument), params_size, &argument_size))
		return -EOVERFLOW;
	argument = calloc(1, argument_size);
	if (!argument)
		return -ENOMEM;

	argument->id = object.id;
	argument->op = operation;
	argument->num_params = num_params;
	if (num_params)
		memcpy(argument->params, params, params_size);
	data.buf_ptr = (uintptr_t)argument;
	data.buf_len = argument_size;
	if (ioctl(fd, TEE_IOC_OBJECT_INVOKE, &data) < 0) {
		error = report_errno("TEE_IOC_OBJECT_INVOKE");
		goto out;
	}
	if (num_params)
		memcpy(params, argument->params, params_size);
	if (secure_result)
		*secure_result = argument->ret;

out:
	free(argument);
	return error;
}

static int object_release(int fd, struct qtee_object *object)
{
	uint32_t secure_result = 0;
	int error;

	if (!object || object->id == TEE_OBJREF_NULL)
		return 0;
	error = object_invoke(fd, *object, QCOMTEE_OBJECT_OP_RELEASE, NULL, 0,
			      &secure_result);
	object->id = TEE_OBJREF_NULL;
	object->flags = 0;
	if (error)
		return error;
	return secure_result ? -EREMOTEIO : 0;
}

static struct tee_ioctl_param ubuf_input(const void *pointer, size_t size)
{
	struct tee_ioctl_param parameter = {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_INPUT,
	};

	parameter.a = (uintptr_t)pointer;
	parameter.b = size;
	return parameter;
}

static struct tee_ioctl_param objref_input(struct qtee_object object)
{
	struct tee_ioctl_param parameter = {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_OBJREF_INPUT,
	};

	parameter.a = object.id;
	parameter.b = object.flags;
	return parameter;
}

static struct tee_ioctl_param objref_output(void)
{
	struct tee_ioctl_param parameter = {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_OBJREF_OUTPUT,
	};

	parameter.a = TEE_OBJREF_NULL;
	return parameter;
}

static int shared_memory_alloc(int tee_fd, size_t size,
			       struct qtee_shared_memory *memory)
{
	struct tee_ioctl_shm_alloc_data data = {
		.size = size,
	};
	int fd;

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
	memset(memory->data, 0, memory->size);
	return 0;
}

static void shared_memory_release(struct qtee_shared_memory *memory)
{
	if (memory->data)
		munmap(memory->data, memory->size);
	if (memory->fd >= 0)
		close(memory->fd);
	memory->data = NULL;
	memory->size = 0;
	memory->id = -1;
	memory->fd = -1;
}

static size_t cbor_uint(uint8_t *buffer, size_t offset, uint64_t value)
{
	if (value < 24U) {
		buffer[offset++] = (uint8_t)value;
	} else if (value <= UINT8_MAX) {
		buffer[offset++] = 0x18;
		buffer[offset++] = (uint8_t)value;
	} else if (value <= UINT16_MAX) {
		buffer[offset++] = 0x19;
		buffer[offset++] = value >> 8;
		buffer[offset++] = value;
	} else if (value <= UINT32_MAX) {
		buffer[offset++] = 0x1a;
		buffer[offset++] = value >> 24;
		buffer[offset++] = value >> 16;
		buffer[offset++] = value >> 8;
		buffer[offset++] = value;
	} else {
		buffer[offset++] = 0x1b;
		buffer[offset++] = value >> 56;
		buffer[offset++] = value >> 48;
		buffer[offset++] = value >> 40;
		buffer[offset++] = value >> 32;
		buffer[offset++] = value >> 24;
		buffer[offset++] = value >> 16;
		buffer[offset++] = value >> 8;
		buffer[offset++] = value;
	}
	return offset;
}

static int credentials_init(struct supplicant *supplicant)
{
	struct timespec now;
	uint64_t milliseconds;
	size_t offset = 0;

	if (clock_gettime(CLOCK_REALTIME, &now))
		return report_errno("clock_gettime");
	milliseconds = (uint64_t)now.tv_sec * 1000U +
		       (uint64_t)now.tv_nsec / 1000000U;
	supplicant->credentials[offset++] = 0xa2; /* map(2) */
	offset = cbor_uint(supplicant->credentials, offset, 1);
	offset = cbor_uint(supplicant->credentials, offset, (uint32_t)getuid());
	offset = cbor_uint(supplicant->credentials, offset, 6);
	offset = cbor_uint(supplicant->credentials, offset, milliseconds);
	if (offset > sizeof(supplicant->credentials))
		return -EOVERFLOW;
	supplicant->credentials_size = offset;
	return 0;
}

struct callback_packet {
	uint32_t value;
	uint32_t num_params;
	struct tee_ioctl_param params[MAX_CALLBACK_PARAMS + 1U];
};

static int dispatch_credentials(struct supplicant *supplicant,
				uint32_t operation,
				struct tee_ioctl_param *params,
				uint32_t num_params, uint8_t *output,
				size_t output_size)
{
	if (operation == 0U) {
		if (num_params != 1U ||
		    params[0].attr != TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_OUTPUT ||
		    params[0].b < sizeof(uint64_t) ||
		    output_size < sizeof(uint64_t))
			return QCOMTEE_ERROR_INVALID;
		put_le64(output, supplicant->credentials_size);
		params[0].a = (uintptr_t)output;
		params[0].b = sizeof(uint64_t);
		return QCOMTEE_OK;
	}
	if (operation == 1U) {
		uint64_t offset;
		size_t count;

		if (num_params != 2U ||
		    params[0].attr != TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_INPUT ||
		    params[0].b != sizeof(uint64_t) ||
		    params[1].attr != TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_OUTPUT)
			return QCOMTEE_ERROR_INVALID;
		offset = get_le64((const void *)(uintptr_t)params[0].a);
		if (offset >= supplicant->credentials_size)
			return QCOMTEE_ERROR_INVALID;
		count = supplicant->credentials_size - (size_t)offset;
		if (count > params[1].b)
			count = params[1].b;
		if (count > output_size)
			return QCOMTEE_ERROR_INVALID;
		memcpy(output, supplicant->credentials + offset, count);
		params[1].a = (uintptr_t)output;
		params[1].b = count;
		return QCOMTEE_OK;
	}

	return QCOMTEE_ERROR_INVALID;
}

static int dispatch_listener(struct listener *listener, uint32_t operation,
			     struct tee_ioctl_param *params,
			     uint32_t num_params, uint32_t *is_64)
{
	uint8_t *temporary;
	uint32_t service_operation;
	int dispatch_error;
	unsigned int i;

	if (operation == 1U) {
		if (num_params)
			return QCOMTEE_ERROR_INVALID;
		pthread_mutex_lock(&listener->call_lock);
		pthread_mutex_unlock(&listener->call_lock);
		return QCOMTEE_OK;
	}
	if (operation != 0U || num_params != 6U ||
	    params[0].attr != TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_OUTPUT ||
	    params[1].attr != TEE_IOCTL_PARAM_ATTR_TYPE_UBUF_OUTPUT ||
	    params[1].b < sizeof(*is_64))
		return QCOMTEE_ERROR_INVALID;
	for (i = 2U; i < 6U; i++)
		if (params[i].attr != TEE_IOCTL_PARAM_ATTR_TYPE_OBJREF_OUTPUT)
			return QCOMTEE_ERROR_INVALID;

	temporary = malloc(listener->memory.size);
	if (!temporary)
		return QCOMTEE_ERROR;
	pthread_mutex_lock(&listener->call_lock);
	memcpy(temporary, listener->memory.data, listener->memory.size);
	service_operation = get_le32(temporary);
	if (listener->id == FS_LISTENER_ID)
		dispatch_error = fs_dispatch(listener->storage, temporary,
					     listener->memory.size);
	else
		dispatch_error = gpfs_dispatch(listener->storage, temporary,
					       listener->memory.size);
	if (!dispatch_error)
		memcpy(listener->memory.data, temporary, listener->memory.size);
	pthread_mutex_unlock(&listener->call_lock);
	free(temporary);
	if (dispatch_error)
		return QCOMTEE_ERROR;

	params[0].a = 0;
	params[0].b = 0;
	*is_64 = 0;
	params[1].a = (uintptr_t)is_64;
	params[1].b = sizeof(*is_64);
	for (i = 2U; i < 6U; i++) {
		params[i].a = TEE_OBJREF_NULL;
		params[i].b = 0;
	}

	if (listener->id == FS_LISTENER_ID) {
		fprintf(stdout, "listener 0x%x op 0x%x -> result %" PRId32 "\n",
			listener->id, service_operation,
			get_le32s(listener->memory.data + 4U));
		fflush(stdout);
	}
	return QCOMTEE_OK;
}

static void fail_worker(struct supplicant *supplicant, const char *operation,
			int error)
{
	errno = error;
	report_errno(operation);
	atomic_store_explicit(&supplicant->worker_failed, true,
			      memory_order_relaxed);
	stop_requested = 1;
	pthread_kill(supplicant->main_thread, SIGUSR1);
}

static void *worker_main(void *argument)
{
	struct supplicant *supplicant = argument;
	uint64_t input_buffer[CALLBACK_INPUT_SIZE / sizeof(uint64_t)];
	uint8_t output_buffer[64];
	struct callback_packet packet;
	struct tee_ioctl_buf_data data;

	while (!stop_requested) {
		uint64_t object_id;
		uint64_t request_id;
		uint32_t operation;
		uint32_t result;
		uint32_t is_64 = 0;
		uint32_t num_params;
		size_t packet_size;

		memset(&packet, 0, sizeof(packet));
		packet.num_params = ARRAY_SIZE(packet.params);
		packet.params[0].attr =
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT |
			TEE_IOCTL_PARAM_ATTR_META;
		packet.params[0].a = (uintptr_t)input_buffer;
		packet.params[0].b = sizeof(input_buffer);
		data.buf_ptr = (uintptr_t)&packet;
		data.buf_len = sizeof(packet);
		if (ioctl(supplicant->tee_fd, TEE_IOC_SUPPL_RECV, &data)) {
			int receive_error = errno;

			if (receive_error == EINTR)
				continue;
			if (!stop_requested)
				fail_worker(supplicant, "TEE_IOC_SUPPL_RECV",
					    receive_error);
			break;
		}
		operation = packet.value;
		num_params = packet.num_params;
		if (!num_params || num_params > ARRAY_SIZE(packet.params)) {
			fprintf(stderr, "invalid callback parameter count %u\n",
				num_params);
			fail_worker(supplicant, "invalid callback packet", EPROTO);
			break;
		}
		object_id = packet.params[0].a;
		request_id = packet.params[0].b;
		if (operation == QCOMTEE_OBJECT_OP_RELEASE)
			continue;

		memset(output_buffer, 0, sizeof(output_buffer));
		if (object_id == CREDENTIALS_OBJECT_ID) {
			result = dispatch_credentials(supplicant, operation,
						      packet.params + 1U,
						      num_params - 1U,
						      output_buffer,
						      sizeof(output_buffer));
		} else if (object_id == FS_OBJECT_ID) {
			result = dispatch_listener(&supplicant->fs, operation,
						   packet.params + 1U,
						   num_params - 1U, &is_64);
		} else if (object_id == GPFS_OBJECT_ID) {
			result = dispatch_listener(&supplicant->gpfs, operation,
						   packet.params + 1U,
						   num_params - 1U, &is_64);
		} else {
			result = QCOMTEE_ERROR_INVALID;
		}

		packet.value = result;
		packet.params[0].attr =
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT |
			TEE_IOCTL_PARAM_ATTR_META;
		packet.params[0].a = request_id;
		packet.params[0].b = 0;
		packet.params[0].c = 0;
		packet_size = offsetof(struct callback_packet, params) +
			      (size_t)num_params * sizeof(packet.params[0]);
		data.buf_ptr = (uintptr_t)&packet;
		data.buf_len = packet_size;
		while (ioctl(supplicant->tee_fd, TEE_IOC_SUPPL_SEND, &data)) {
			int send_error = errno;

			if (send_error == EINTR && !stop_requested)
				continue;
			if (send_error == EINVAL && !stop_requested) {
				fprintf(stderr,
					"callback request %" PRIu64
					" was canceled before its response\n",
					request_id);
				fflush(stderr);
				break;
			}
			if (!stop_requested)
				fail_worker(supplicant, "TEE_IOC_SUPPL_SEND",
					    send_error);
			break;
		}
	}

	return NULL;
}

static int sync_path_parent(const char *path)
{
	char *copy;
	char *slash;
	size_t length;
	int error = 0;
	int fd;

	copy = strdup(path);
	if (!copy)
		return ENOMEM;
	length = strlen(copy);
	while (length > 1U && copy[length - 1U] == '/')
		copy[--length] = '\0';
	slash = strrchr(copy, '/');
	if (!slash) {
		free(copy);
		copy = strdup(".");
		if (!copy)
			return ENOMEM;
	} else if (slash == copy) {
		slash[1] = '\0';
	} else {
		*slash = '\0';
	}

	fd = open(copy, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		error = errno;
	} else {
		if (fsync(fd))
			error = errno;
		close(fd);
	}
	free(copy);
	return error;
}

static int storage_init(struct storage_backend *storage, const char *root)
{
	struct stat status;
	bool created = false;
	unsigned int i;
	int error;

	memset(storage, 0, sizeof(*storage));
	storage->root_fd = -1;
	for (i = 0; i < MAX_FS_HANDLES; i++)
		storage->handles[i].fd = -1;
	if (!mkdir(root, 0700)) {
		created = true;
	} else if (errno != EEXIST) {
		return report_errno("create state root");
	}
	if (created) {
		error = sync_path_parent(root);
		if (error) {
			errno = error;
			return report_errno("sync state root parent");
		}
	}
	if (lstat(root, &status))
		return report_errno("stat state root");
	if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
		fprintf(stderr, "state root must be a real directory: %s\n", root);
		return -ENOTDIR;
	}
	storage->root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
					 O_CLOEXEC);
	if (storage->root_fd < 0)
		return report_errno("open state root");
	error = pthread_mutex_init(&storage->lock, NULL);
	if (error) {
		close(storage->root_fd);
		storage->root_fd = -1;
		return -error;
	}
	return 0;
}

static void storage_destroy(struct storage_backend *storage)
{
	unsigned int i;

	for (i = 0; i < MAX_FS_HANDLES; i++) {
		if (storage->handles[i].fd >= 0)
			close(storage->handles[i].fd);
		storage->handles[i].fd = -1;
	}
	if (storage->root_fd >= 0)
		close(storage->root_fd);
	storage->root_fd = -1;
	pthread_mutex_destroy(&storage->lock);
}

static int get_client_environment(struct supplicant *supplicant,
				  struct qtee_object *client_environment)
{
	const struct qtee_object root = {
		.id = TEE_OBJREF_NULL,
	};
	const struct qtee_object credentials = {
		.id = CREDENTIALS_OBJECT_ID,
		.flags = QCOMTEE_OBJREF_FLAG_USER,
	};
	struct tee_ioctl_param params[2];
	uint32_t result = 0;
	int error;

	params[0] = objref_input(credentials);
	params[1] = objref_output();
	error = object_invoke(supplicant->tee_fd, root,
			      ROOT_OP_REGISTER_AS_CLIENT, params,
			      ARRAY_SIZE(params), &result);
	if (error)
		return error;
	if (result || params[1].a == TEE_OBJREF_NULL ||
	    !(params[1].b & QCOMTEE_OBJREF_FLAG_TEE)) {
		fprintf(stderr, "registerAsClient failed: 0x%08x\n", result);
		return -EREMOTEIO;
	}
	client_environment->id = params[1].a;
	client_environment->flags = params[1].b;
	return 0;
}

static int open_register_service(struct supplicant *supplicant,
				 struct qtee_object client_environment,
				 struct qtee_object *service)
{
	uint32_t uid = REGISTER_LISTENER_UID;
	struct tee_ioctl_param params[2];
	uint32_t result = 0;
	int error;

	params[0] = ubuf_input(&uid, sizeof(uid));
	params[1] = objref_output();
	error = object_invoke(supplicant->tee_fd, client_environment,
			      CLIENT_ENV_OP_OPEN, params, ARRAY_SIZE(params),
			      &result);
	if (error)
		return error;
	if (result || params[1].a == TEE_OBJREF_NULL ||
	    !(params[1].b & QCOMTEE_OBJREF_FLAG_TEE)) {
		fprintf(stderr, "open listener registration service failed: 0x%08x\n",
			result);
		return -EREMOTEIO;
	}
	service->id = params[1].a;
	service->flags = params[1].b;
	return 0;
}

static int register_listener(struct supplicant *supplicant,
			     struct listener *listener)
{
	struct qtee_object callback = {
		.id = listener->object_id,
		.flags = QCOMTEE_OBJREF_FLAG_USER,
	};
	struct qtee_object memory = {
		.id = (uint64_t)(uint32_t)listener->memory.id,
		.flags = QCOMTEE_OBJREF_FLAG_MEM,
	};
	uint32_t listener_id = listener->id;
	struct tee_ioctl_param params[3];
	uint32_t result = 0;
	int error;

	params[0] = ubuf_input(&listener_id, sizeof(listener_id));
	params[1] = objref_input(callback);
	params[2] = objref_input(memory);
	error = object_invoke(supplicant->tee_fd, supplicant->register_service,
			      REGISTER_LISTENER_OP_REGISTER, params,
			      ARRAY_SIZE(params), &result);
	if (error)
		return error;
	if (result) {
		fprintf(stderr, "register listener 0x%x failed: 0x%08x\n",
			listener->id, result);
		return -EREMOTEIO;
	}
	fprintf(stdout, "registered listener 0x%x (%zu-byte shared buffer)\n",
		listener->id, listener->memory.size);
	fflush(stdout);
	return 0;
}

static int start_workers(struct supplicant *supplicant)
{
	unsigned int i;

	for (i = 0; i < MAX_WORKERS; i++) {
		int error = pthread_create(&supplicant->workers[i], NULL,
					   worker_main, supplicant);

		if (error)
			return -error;
		supplicant->workers_started++;
	}
	return 0;
}

static void stop_workers(struct supplicant *supplicant)
{
	size_t i;

	stop_requested = 1;
	for (i = 0; i < supplicant->workers_started; i++)
		pthread_kill(supplicant->workers[i], SIGUSR1);
	for (i = 0; i < supplicant->workers_started; i++)
		pthread_join(supplicant->workers[i], NULL);
	supplicant->workers_started = 0;
}

static int listener_init(struct supplicant *supplicant,
			 struct listener *listener, uint32_t id,
			 uint64_t object_id, size_t size)
{
	int error;

	listener->id = id;
	listener->object_id = object_id;
	listener->memory.fd = -1;
	listener->memory.id = -1;
	listener->storage = &supplicant->storage;
	error = pthread_mutex_init(&listener->call_lock, NULL);
	if (error)
		return -error;
	error = shared_memory_alloc(supplicant->tee_fd, size, &listener->memory);
	if (error) {
		pthread_mutex_destroy(&listener->call_lock);
		return error;
	}
	return 0;
}

static void listener_destroy(struct listener *listener)
{
	shared_memory_release(&listener->memory);
	pthread_mutex_destroy(&listener->call_lock);
}

static int supplicant_start(struct supplicant *supplicant, const char *device,
			    const char *state_root)
{
	struct qtee_object client_environment = {
		.id = TEE_OBJREF_NULL,
	};
	bool storage_ready = false;
	bool fs_ready = false;
	bool gpfs_ready = false;
	int error;

	memset(supplicant, 0, sizeof(*supplicant));
	atomic_init(&supplicant->worker_failed, false);
	supplicant->main_thread = pthread_self();
	supplicant->tee_fd = -1;
	supplicant->register_service.id = TEE_OBJREF_NULL;
	error = storage_init(&supplicant->storage, state_root);
	if (error)
		return error;
	storage_ready = true;
	supplicant->tee_fd = open(device, O_RDWR | O_CLOEXEC);
	if (supplicant->tee_fd < 0) {
		error = report_errno(device);
		goto failed;
	}
	error = credentials_init(supplicant);
	if (error)
		goto failed;
	error = listener_init(supplicant, &supplicant->fs, FS_LISTENER_ID,
			      FS_OBJECT_ID, FS_BUFFER_SIZE);
	if (error)
		goto failed;
	fs_ready = true;
	error = listener_init(supplicant, &supplicant->gpfs, GPFS_LISTENER_ID,
			      GPFS_OBJECT_ID, GPFS_BUFFER_SIZE);
	if (error)
		goto failed;
	gpfs_ready = true;
	error = start_workers(supplicant);
	if (error)
		goto failed;
	error = get_client_environment(supplicant, &client_environment);
	if (error)
		goto failed;
	error = open_register_service(supplicant, client_environment,
				      &supplicant->register_service);
	object_release(supplicant->tee_fd, &client_environment);
	if (error)
		goto failed;
	error = register_listener(supplicant, &supplicant->fs);
	if (error)
		goto failed;
	error = register_listener(supplicant, &supplicant->gpfs);
	if (error)
		goto failed;
	return 0;

failed:
	object_release(supplicant->tee_fd, &client_environment);
	object_release(supplicant->tee_fd, &supplicant->register_service);
	if (supplicant->workers_started)
		stop_workers(supplicant);
	if (gpfs_ready)
		listener_destroy(&supplicant->gpfs);
	if (fs_ready)
		listener_destroy(&supplicant->fs);
	if (supplicant->tee_fd >= 0)
		close(supplicant->tee_fd);
	supplicant->tee_fd = -1;
	if (storage_ready)
		storage_destroy(&supplicant->storage);
	return error;
}

static void supplicant_destroy(struct supplicant *supplicant)
{
	object_release(supplicant->tee_fd, &supplicant->register_service);
	stop_workers(supplicant);
	listener_destroy(&supplicant->gpfs);
	listener_destroy(&supplicant->fs);
	close(supplicant->tee_fd);
	supplicant->tee_fd = -1;
	storage_destroy(&supplicant->storage);
}

static int set_test_path(uint8_t *field, const char *path)
{
	size_t length = strlen(path);

	if (length >= FS_PATH_SIZE)
		return -1;
	memset(field, 0, FS_PATH_SIZE);
	memcpy(field, path, length);
	return 0;
}

#define SELFTEST_REQUIRE(condition, message)                         \
	do {                                                          \
		if (!(condition)) {                                     \
			fprintf(stderr, "self-test failed: %s\n", message); \
			goto out;                                         \
		}                                                     \
	} while (0)

static int run_self_test(const char *state_root)
{
	static const char vector_path[] = "/data/vendor/fpdump/vector.so";
	static const char renamed_path[] = "/data/vendor/fpdump/renamed.so";
	static const uint8_t original[] = { 0x11, 0x22, 0x33, 0x44 };
	static const uint8_t replacement[] = { 0xaa, 0xbb };
	struct storage_backend storage;
	uint8_t *gpfs = NULL;
	uint8_t *fs = NULL;
	int virtual_handle;
	int result = -1;
	int error;

	error = storage_init(&storage, state_root);
	if (error)
		return error;
	gpfs = calloc(1, GPFS_BUFFER_SIZE);
	fs = calloc(1, FS_BUFFER_SIZE);
	SELFTEST_REQUIRE(gpfs && fs, "allocate protocol buffers");

	put_le32(gpfs, GPFS_VERSION_OP);
	SELFTEST_REQUIRE(!gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE),
			 "dispatch GPFS version");
	SELFTEST_REQUIRE(get_le32(gpfs) == GPFS_VERSION_OP &&
			 get_le32(gpfs + 4U) == 2U && !get_le32(gpfs + 8U),
			 "GPFS version response layout");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 1);
	SELFTEST_REQUIRE(!set_test_path(gpfs + 4U, vector_path),
			 "set write path");
	put_le32(gpfs + 260U, 0);
	put_le32(gpfs + 264U, sizeof(original));
	memcpy(gpfs + 272U, original, sizeof(original));
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U) &&
			 get_le32(gpfs + 8U) == sizeof(original),
			 "GPFS automatic write");

	put_le32(fs, FS_OP_OPEN);
	SELFTEST_REQUIRE(!set_test_path(fs + 4U, vector_path),
			 "set listener 10 path");
	put_le32(fs + 260U, O_RDONLY);
	fs_dispatch(&storage, fs, FS_BUFFER_SIZE);
	virtual_handle = get_le32s(fs + 4U);
	SELFTEST_REQUIRE(virtual_handle > 0, "listener 10 sees GPFS object");
	memset(fs, 0, FS_BUFFER_SIZE);
	put_le32(fs, FS_OP_READ);
	put_le32(fs + 4U, (uint32_t)virtual_handle);
	put_le32(fs + 8U, sizeof(original));
	fs_dispatch(&storage, fs, FS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32s(fs + 20004U) == (int32_t)sizeof(original) &&
			 !memcmp(fs + 4U, original, sizeof(original)),
			 "listener 10 read through virtual handle");
	memset(fs, 0, FS_BUFFER_SIZE);
	put_le32(fs, FS_OP_CLOSE);
	put_le32(fs + 4U, (uint32_t)virtual_handle);
	fs_dispatch(&storage, fs, FS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32s(fs + 4U), "close virtual handle");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 0);
	set_test_path(gpfs + 4U, vector_path);
	put_le32(gpfs + 260U, 1);
	put_le32(gpfs + 264U, 2);
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U) && get_le32(gpfs + 8U) == 2U &&
			 gpfs[12] == 0x22 && gpfs[13] == 0x33,
			 "GPFS automatic read with offset");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 1);
	set_test_path(gpfs + 4U, vector_path);
	put_le32(gpfs + 264U, sizeof(replacement));
	put_le32(gpfs + 268U, 1);
	memcpy(gpfs + 272U, replacement, sizeof(replacement));
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U), "atomic replacement with backup");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 0);
	set_test_path(gpfs + 4U, vector_path);
	put_le32(gpfs + 264U, sizeof(original));
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U) &&
			 get_le32(gpfs + 8U) == sizeof(replacement) &&
			 !memcmp(gpfs + 12U, replacement, sizeof(replacement)),
			 "offset-zero replacement truncates destination");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 0);
	set_test_path(gpfs + 4U, "/data/vendor/fpdump/vector.so.bak");
	put_le32(gpfs + 264U, sizeof(original));
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U) &&
			 get_le32(gpfs + 8U) == sizeof(original) &&
			 !memcmp(gpfs + 12U, original, sizeof(original)),
			 "backup contains pre-replacement bytes");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 3);
	set_test_path(gpfs + 4U, vector_path);
	set_test_path(gpfs + 260U, renamed_path);
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U), "GPFS automatic rename");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 2);
	set_test_path(gpfs + 4U, renamed_path);
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U), "GPFS automatic remove");
	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 0);
	set_test_path(gpfs + 4U, renamed_path);
	put_le32(gpfs + 264U, 1);
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32(gpfs + 4U) == ENOENT &&
			 !get_le32(gpfs + 8U), "missing GPFS object reports ENOENT");

	memset(fs, 0, FS_BUFFER_SIZE);
	put_le32(fs, FS_OP_OPEN);
	set_test_path(fs + 4U, "/missing.so");
	put_le32(fs + 260U, O_RDONLY);
	fs_dispatch(&storage, fs, FS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32s(fs + 4U) == -1,
			 "listener 10 missing open returns -1");
	memset(fs, 0, FS_BUFFER_SIZE);
	put_le32(fs, FS_OP_GET_ERRNO);
	fs_dispatch(&storage, fs, FS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32s(fs + 4U) == ENOENT,
			 "listener 10 exposes positive errno");

	memset(fs, 0, FS_BUFFER_SIZE);
	put_le32(fs, FS_OP_CLOSE);
	put_le32(fs + 4U, (uint32_t)storage.root_fd);
	fs_dispatch(&storage, fs, FS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32s(fs + 4U) == -1,
			 "raw host descriptor is not a virtual handle");
	memset(fs, 0, FS_BUFFER_SIZE);
	put_le32(fs, FS_OP_GET_ERRNO);
	fs_dispatch(&storage, fs, FS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32s(fs + 4U) == EBADF,
			 "forged handle reports EBADF");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 1);
	set_test_path(gpfs + 4U, "../escape");
	put_le32(gpfs + 264U, 1);
	gpfs[272] = 1;
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32(gpfs + 4U) == EINVAL,
			 "parent traversal is rejected");

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 1);
	memcpy(gpfs + 4U, "safe-longer", sizeof("safe-longer"));
	memcpy(gpfs + 4U, "safe", sizeof("safe"));
	put_le32(gpfs + 264U, 1);
	gpfs[272] = 1;
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(!get_le32(gpfs + 4U),
			 "shorter path accepts stale shared-buffer padding");
	unlinkat(storage.root_fd, "safe", 0);

	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 1);
	memset(gpfs + 4U, 'a', FS_PATH_SIZE);
	put_le32(gpfs + 264U, 1);
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32(gpfs + 4U) == EINVAL,
			 "unterminated path is rejected");

	unlinkat(storage.root_fd, "outside", 0);
	SELFTEST_REQUIRE(!symlinkat("/tmp", storage.root_fd, "outside"),
			 "create self-test symlink");
	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 1);
	set_test_path(gpfs + 4U, "/outside/qtee-fs-must-not-exist");
	put_le32(gpfs + 264U, 1);
	gpfs[272] = 1;
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32(gpfs + 4U) != 0,
			 "symlink parent is rejected");
	unlinkat(storage.root_fd, "outside", 0);

	unlinkat(storage.root_fd, "directory-object", AT_REMOVEDIR);
	SELFTEST_REQUIRE(!mkdirat(storage.root_fd, "directory-object", 0700),
			 "create non-regular object");
	memset(gpfs, 0, GPFS_BUFFER_SIZE);
	put_le32(gpfs, 0);
	set_test_path(gpfs + 4U, "/directory-object");
	put_le32(gpfs + 264U, 1);
	gpfs_dispatch(&storage, gpfs, GPFS_BUFFER_SIZE);
	SELFTEST_REQUIRE(get_le32(gpfs + 4U) == EINVAL,
			 "non-regular GPFS object is rejected");
	unlinkat(storage.root_fd, "directory-object", AT_REMOVEDIR);

	result = 0;
	puts("qcomtee-fs-supplicant self-test: PASS");

out:
	free(fs);
	free(gpfs);
	storage_destroy(&storage);
	return result;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s [--device DEVICE] [--state-root DIRECTORY] [--self-test]\n",
		program);
}

int main(int argc, char **argv)
{
	const char *device = "/dev/tee0";
	const char *state_root = "/var/lib/xiaomi-fingerprint";
	struct sigaction stop_action = {
		.sa_handler = handle_stop,
	};
	struct sigaction wakeup_action = {
		.sa_handler = handle_wakeup,
	};
	struct supplicant supplicant;
	bool worker_failed;
	bool self_test = false;
	int i;
	int error;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--device")) {
			if (++i >= argc) {
				usage(argv[0]);
				return EXIT_FAILURE;
			}
			device = argv[i];
		} else if (!strcmp(argv[i], "--state-root")) {
			if (++i >= argc) {
				usage(argv[0]);
				return EXIT_FAILURE;
			}
			state_root = argv[i];
		} else if (!strcmp(argv[i], "--self-test")) {
			self_test = true;
		} else if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return EXIT_SUCCESS;
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (self_test)
		return run_self_test(state_root) ? EXIT_FAILURE : EXIT_SUCCESS;

	sigemptyset(&stop_action.sa_mask);
	sigemptyset(&wakeup_action.sa_mask);
	if (sigaction(SIGINT, &stop_action, NULL) ||
	    sigaction(SIGTERM, &stop_action, NULL) ||
	    sigaction(SIGHUP, &stop_action, NULL) ||
	    sigaction(SIGUSR1, &wakeup_action, NULL)) {
		perror("sigaction");
		return EXIT_FAILURE;
	}
	stop_requested = 0;
	error = supplicant_start(&supplicant, device, state_root);
	if (error)
		return EXIT_FAILURE;
	fprintf(stdout,
		"qcomtee filesystem supplicant ready: state root %s, workers %u\n",
		state_root, MAX_WORKERS);
	fflush(stdout);
	while (!stop_requested)
		pause();
	worker_failed = atomic_load_explicit(&supplicant.worker_failed,
					     memory_order_relaxed);
	supplicant_destroy(&supplicant);
	return worker_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
