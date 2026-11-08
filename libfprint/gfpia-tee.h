/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Talking to a Qualcomm Trusted Execution Environment application.
 *
 * This is the transport the fingerprint protocol rides on, and nothing in it
 * knows anything about fingerprints: it opens the qcomtee device, reaches the
 * QSEECom compatibility loader, loads an application from a split MDT image,
 * and carries a request and its payload to that application and back.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/tee.h>

/* A reference QTEE handed back. */
struct qtee_object {
	uint64_t id;
	uint64_t flags;
};

/* A length and the bytes that go with it. */
struct blob {
	uint8_t *data;
	size_t size;
};

/* Memory both this process and QTEE can see. */
struct qtee_shared_memory {
	uint8_t *data;
	size_t size;
	int32_t id;
	int fd;
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(n) (UINT64_C(1) << (n))

/* How the qcomtee driver labels the two kinds of reference it hands out. */
#define QCOMTEE_OBJREF_FLAG_TEE BIT(0)
#define QCOMTEE_OBJREF_FLAG_MEM BIT(2)
#define QCOMTEE_OBJECT_OP_RELEASE UINT32_C(0xffff)

/* The root object, and the two things a client environment will do. */
#define QTEE_OBJ_ROOT UINT64_C(1)
#define CLIENT_ENV_OP_OPEN UINT32_C(0)
#define CLIENT_ENV_OP_REGISTER_LEGACY UINT32_C(1)

/* The application loader, and the one operation a loaded application answers. */
#define APP_LOADER_OP_LOAD_FROM_REGION UINT32_C(0)
#define APP_LOADER_OP_LOAD_FROM_BUFFER UINT32_C(1)
#define APP_LOADER_OP_LOOKUP_TA UINT32_C(2)
#define APP_LOADER_ERROR_APP_NOT_LOADED UINT32_C(23)
#define QTEE_OBJECT_ERROR_INVALID UINT32_C(2)
#define QSEECOM_COMPAT_OP_SEND_REQUEST UINT32_C(0)

/*
 * The QSEECom compatibility loader. Its own UID, and the operation that drops
 * a loaded application.
 */
#define QSEECOM_APP_LOADER_UID UINT32_C(122)
#define QSEECOM_APP_CONTROLLER_OP_UNLOAD UINT32_C(1)

/*
 * An invocation carries at most four megabytes, so anything larger than that
 * minus a page of headroom has to go in as a memory object instead of inline.
 */
#define MAX_APP_NAME_SIZE 64U
#define MAX_DIST_NAME_SIZE 256U
#define MAX_QTEE_INBOUND_SIZE (4U * 1024U * 1024U)
#define MAX_INLINE_IMAGE_SIZE (MAX_QTEE_INBOUND_SIZE - 4096U)
#define MAX_APP_IMAGE_SIZE (64U * 1024U * 1024U)

int report_errno(const char *what);

uint32_t read_le32(const uint8_t *data);
uint16_t read_le16(const uint8_t *data);
uint64_t read_le64(const uint8_t *data);
void write_le32(uint8_t *data, uint32_t value);
void write_le64(uint8_t *data, uint64_t value);

void secure_clear(void *data, size_t size);
void secure_free_blob(struct blob *blob);

/**
 * find_qcomtee_device() - Locate the TEE device the qcomtee driver owns.
 * @path: where to write the device path.
 * @path_size: how much room @path has.
 *
 * Return: An open descriptor for that device on success, < 0 on failure. The
 * caller owns it.
 */
int find_qcomtee_device(char *path, size_t path_size);

int object_invoke(int fd, struct qtee_object object, uint32_t op,
		  struct tee_ioctl_param *params, uint32_t num_params,
		  uint32_t *secure_result);
int object_release(int fd, struct qtee_object *object);

int shared_memory_alloc(int tee_fd, size_t size,
			struct qtee_shared_memory *memory);
void shared_memory_release(struct qtee_shared_memory *memory);
void secure_shared_memory_release(struct qtee_shared_memory *memory);

int read_file(const char *path, size_t maximum, struct blob *blob);

/**
 * get_client_env() - Take the client environment QTEE offers this process.
 * @fd: open TEE device.
 * @client_env: where to leave the reference.
 *
 * Return: Zero on success, < 0 on failure.
 */
int get_client_env(int fd, struct qtee_object *client_env);

/**
 * client_env_open() - Ask the client environment for one of QTEE's services.
 * @fd: open TEE device.
 * @client_env: the client environment.
 * @uid: which service.
 * @service: where to leave the reference.
 *
 * Return: Zero on success, < 0 on failure.
 */
int client_env_open(int fd, struct qtee_object client_env, uint32_t uid,
		    struct qtee_object *service);

/**
 * start_app() - Get an application running and take its controller.
 * @fd: open TEE device.
 * @loader: the application loader service.
 * @app_name: the application's name.
 * @source: a reconstructed ELF, or a directory holding its split image.
 * @controller: where to leave the controller.
 *
 * Return: Zero on success, < 0 on failure.
 */
int start_app(int fd, struct qtee_object loader, const char *app_name,
	      const char *source, struct qtee_object *controller);

/**
 * app_unload() - Ask QTEE to drop a loaded application.
 * @fd: open TEE device.
 * @controller: controller the loader handed back.
 *
 * Releasing the controller is not enough on its own: QTEE keeps the
 * application resident and the next load reports that it is already there.
 */
void app_unload(int fd, struct qtee_object controller);

/**
 * send_request() - Carry one request and its payload to an application.
 * @fd: open TEE device.
 * @controller: the loaded application.
 * @request: the request; QTEE patches the payload's address into its first
 *           eight bytes, which must therefore be zero.
 * @payload: shared memory the application reads and writes in place.
 * @response_size: how many bytes of answer to make room for.
 * @request_output: where to leave the request as QTEE patched it.
 * @response: where to leave the answer.
 *
 * Return: Zero on success, < 0 on failure.
 */
int send_request(int fd, struct qtee_object controller,
		 const struct blob *request,
		 const struct qtee_shared_memory *payload,
		 size_t response_size, struct blob *request_output,
		 struct blob *response);
