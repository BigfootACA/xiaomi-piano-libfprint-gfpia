// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Minimal QSEECom compatibility client for the generic QTEE object ABI.
 *
 * This intentionally does not emulate /dev/qseecom. Recent Qualcomm targets
 * implement QSEECom compatibility as QTEE objects, which are already exposed
 * by the mainline qcomtee driver through TEE_IOC_OBJECT_INVOKE.
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/tee.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define QCOMTEE_OBJREF_FLAG_TEE BIT(0)
#define QCOMTEE_OBJREF_FLAG_MEM BIT(2)
#define QCOMTEE_OBJECT_OP_RELEASE UINT32_C(0xffff)

#define CLIENT_ENV_OP_OPEN UINT32_C(0)
#define CLIENT_ENV_OP_REGISTER_LEGACY UINT32_C(1)

#define QSEECOM_COMPAT_APP_LOADER_UID UINT32_C(122)
#define APP_LOADER_OP_LOAD_FROM_REGION UINT32_C(0)
#define APP_LOADER_OP_LOAD_FROM_BUFFER UINT32_C(1)
#define APP_LOADER_OP_LOOKUP_TA UINT32_C(2)
#define APP_LOADER_ERROR_APP_NOT_LOADED UINT32_C(23)
#define QTEE_OBJECT_ERROR_INVALID UINT32_C(2)

#define KEYMASTER_APP_CLIENT_UID UINT32_C(151)
#define KEYMASTER_HAL_SERVICE_ID UINT32_C(150)
#define KEYMASTER_OBJECT_OP_SEND_COMMAND UINT32_C(0)
#define KEYMASTER_SHARED_BUFFER_SIZE 0xa000U
#define KEYMASTER_GET_VERSION_COMMAND UINT32_C(0x200)
#define KEYMASTER_GET_VERSION_REQUEST_SIZE sizeof(uint32_t)
#define KEYMASTER_GET_VERSION_RESPONSE_SIZE (5U * sizeof(uint32_t))
#define KEYMASTER_SET_VERSION_COMMAND UINT32_C(0x207)
#define KEYMASTER_SET_VERSION_REQUEST_SIZE (6U * sizeof(uint32_t))
#define KEYMASTER_CLIENT_MAJOR_VERSION UINT32_C(4)
#define KEYMASTER_CLIENT_MINOR_VERSION UINT32_C(5)
#define KEYMASTER_CLIENT_TA_MAJOR_VERSION UINT32_C(4)
#define KEYMASTER_CLIENT_TA_MINOR_VERSION UINT32_C(5)
#define KEYMASTER_KEYMINT_SET_VERSION_COMMAND UINT32_C(0x3121)
#define KEYMASTER_KEYMINT_SET_VERSION_VALUE UINT32_C(300)
#define KEYMASTER_KEYMINT_SET_VERSION_REQUEST_SIZE 9U
#define KEYMASTER_GET_DATE_SUPPORT_COMMAND UINT32_C(0x215)
#define KEYMASTER_GET_DATE_SUPPORT_REQUEST_SIZE 12U
#define KEYMASTER_CONFIGURE_COMMAND UINT32_C(0x2116)
#define KEYMASTER_CONFIGURE_REQUEST_SIZE 37U
#define KEYMASTER_OS_VERSION UINT32_C(160000)
#define KEYMASTER_OS_PATCHLEVEL UINT32_C(20260701)
#define KEYMASTER_VENDOR_PATCHLEVEL UINT32_C(20260201)
#define KEYMASTER_RESPONSE_HEADER_SIZE 8U
#define KEYMASTER_GET_SHARED_HMAC_COMMAND UINT32_C(0x220e)
#define KEYMASTER_COMPUTE_SHARED_HMAC_COMMAND UINT32_C(0x220f)
#define KEYMASTER_HMAC_VALUE_SIZE 32U
#define KEYMASTER_HMAC_RECORD_SIZE (2U * KEYMASTER_HMAC_VALUE_SIZE)
#define KEYMASTER_GET_SHARED_HMAC_REQUEST_SIZE sizeof(uint32_t)
#define KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE 73U
#define KEYMASTER_GET_SHARED_HMAC_SEED_OFFSET 5U
#define KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET 37U
#define KEYMASTER_GET_SHARED_HMAC_NONCE_OFFSET 41U
#define KEYMASTER_COMPUTE_SHARED_HMAC_CBOR_SIZE 69U
#define KEYMASTER_COMPUTE_SHARED_HMAC_REQUEST_SIZE 73U
#define KEYMASTER_COMPUTE_SHARED_HMAC_RECORD_OFFSET 9U
#define KEYMASTER_COMPUTE_SHARED_HMAC_NONCE_OFFSET 41U
#define KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE 37U
#define KEYMASTER_COMPUTE_SHARED_HMAC_CHECK_OFFSET 5U

#define QSEECOM_COMPAT_OP_SEND_REQUEST UINT32_C(0)

/*
 * The sensor reaches this side as a UIO device with no ioctl of any kind:
 * holding it open is what keeps the supply up and the interrupt armed, which
 * is all this program ever wanted from it. xiaomi-fp-run opens it and passes
 * the descriptor down in XIAOMI_FP_FD_ENV.
 */
#define XIAOMI_FP_FD_ENV "XIAOMI_FP_FD"
#define XIAOMI_FP_UIO_NAME "xiaomi-fp-uio"

/*
 * The byte the old driver reported for GET_FW_INFO, which it answered with
 * unconditionally. Command 1001 carries it, so it is still written into the
 * payload - it is just no longer worth asking for.
 */
#define XIAOMI_FP_FW_INFO UINT8_C(0)

#define MAX_APP_NAME_SIZE 64U
#define MAX_DIST_NAME_SIZE 256U
#define MAX_QTEE_INBOUND_SIZE (4U * 1024U * 1024U)
#define MAX_INLINE_IMAGE_SIZE (MAX_QTEE_INBOUND_SIZE - 4096U)
#define MAX_APP_IMAGE_SIZE (64U * 1024U * 1024U)
#define MAX_IO_BUFFER_SIZE MAX_INLINE_IMAGE_SIZE
#define DEFAULT_RESPONSE_SIZE 4096U

#define GFPIA_REQUEST_SIZE 0x80U
#define GFPIA_RESPONSE_SIZE 0x40U
#define GFPIA_109_PAYLOAD_SIZE 0x100U
#define GFPIA_1000_PAYLOAD_SIZE 0x280U
#define GFPIA_1001_PAYLOAD_SIZE 0x168U
#define GFPIA_1005_PAYLOAD_SIZE 0x74U
#define GFPIA_1014_PAYLOAD_SIZE 0x270U
#define GFPIA_1113_PAYLOAD_SIZE 0x7d014U
#define GFPIA_109_COMMAND UINT32_C(109)
#define GFPIA_1000_COMMAND UINT32_C(1000)
#define GFPIA_1001_COMMAND UINT32_C(1001)
#define GFPIA_1005_COMMAND UINT32_C(1005)
#define GFPIA_1014_COMMAND UINT32_C(1014)
#define GFPIA_1113_COMMAND UINT32_C(1113)
#define GFPIA_1060_COMMAND UINT32_C(1060)
#define GFPIA_1016_COMMAND UINT32_C(1016)
#define GFPIA_1015_COMMAND UINT32_C(1015)
#define GFPIA_1012_COMMAND UINT32_C(1012)
#define GFPIA_1006_COMMAND UINT32_C(1006)
#define GFPIA_1007_COMMAND UINT32_C(1007)
#define GFPIA_1008_COMMAND UINT32_C(1008)
#define GFPIA_1010_COMMAND UINT32_C(1010)
/*
 * IAppController::unload(). Releasing the controller is not enough: QTEE keeps
 * the application resident, and the next load returns ALREADY_LOADED. Without
 * this every run needs a reboot to get a fresh TA.
 */
#define QSEECOM_APP_CONTROLLER_OP_UNLOAD UINT32_C(1)
#define GFPIA_1001_MAX_OTP_SIZE UINT32_C(0xc0)
#define GFPIA_1001_MATCH_VERSION UINT8_C(2)
#define GFPIA_COMMON_PAYLOAD_SIZE 0x6cU
#define GFPIA_1060_PAYLOAD_SIZE GFPIA_COMMON_PAYLOAD_SIZE
/*
 * GF_CMD_IRQ. hal_milan_irq() allocates exactly this much, fills in the four
 * input fields below, and sends it as an ordinary class 1 command every time
 * the sensor raises an interrupt. Everything the TA has to say about an
 * enrolment or a match comes back in the same buffer.
 */
#define GFPIA_1016_PAYLOAD_SIZE 0xd134U
#define GFPIA_IRQ_TYPE_OFFSET 0x6cU
#define GFPIA_IRQ_OPERATION_OFFSET 0x70U
#define GFPIA_IRQ_PROGRESS_OFFSET 0x88U
#define GFPIA_IRQ_RESULT_OFFSET 0x94U
#define GFPIA_IRQ_STATE_OFFSET 0x98U
#define GFPIA_IRQ_MODE_OFFSET 0xa8U
#define GFPIA_IRQ_IMAGE_OFFSET 0x2c5U
#define GFPIA_IRQ_DUMP_OFFSET 0xd130U
#define GFPIA_IRQ_STATE_START UINT32_C(1)
#define GFPIA_IRQ_MODE_VALUE UINT32_C(0x200)
#define GFPIA_IRQ_IMAGE_VALUE UINT32_C(0x2000000)
/*
 * hal_milan_irq() does not treat one interrupt as one command. Whenever the
 * state it gets back is one of these it sends GF_CMD_IRQ again, passing the
 * buffer back exactly as the TA left it. Until that conversation finishes the
 * interrupt is not acknowledged, and an edge-triggered sensor whose line is
 * still asserted never raises another one.
 */
#define GFPIA_IRQ_STATE_EVENT UINT32_C(2)
#define GFPIA_IRQ_STATE_AGAIN_FIRST UINT32_C(4)
#define GFPIA_IRQ_STATE_AGAIN_SECOND UINT32_C(5)
#define GFPIA_IRQ_STATE_FRAME UINT32_C(8)
/* Before the state 8 round the HAL clears the frame region. */
#define GFPIA_IRQ_FRAME_OFFSET 0x2f4U
#define GFPIA_IRQ_FRAME_SIZE 0x5a20U
/* A bound of our own: the stock loop trusts the TA to settle. */
#define GFPIA_IRQ_MAX_ROUNDS 32U
/*
 * Enumerate. gf_hal_common_enumerate() sends a payload of nothing but zeroes
 * and reads two parallel arrays back out of it: the group each finger belongs
 * to, and the finger's own identifier. A zero identifier is an empty slot.
 */
#define GFPIA_1015_PAYLOAD_SIZE 0xc0U
#define GFPIA_ENUMERATE_GROUP_OFFSET 0x70U
#define GFPIA_ENUMERATE_FINGER_OFFSET 0x98U
#define GFPIA_ENUMERATE_MAX_FINGERS 10U
/*
 * Save. gf_hal_save() takes a group and a finger and writes nothing else into
 * its payload. The caller does not invent either: gf_hal_common_enroll_success
 * reads both straight out of the interrupt payload the TA has just filled in,
 *
 *   245f4: ldp w0, w1, [x19, #128]   ; irq[0x80], irq[0x84]
 *   245f8: bl  gf_hal_save
 *
 * so the TA is the one that decides which finger it has been building.
 */
#define GFPIA_1012_PAYLOAD_SIZE 0x78U
#define GFPIA_SAVE_GROUP_OFFSET 0x6cU
#define GFPIA_SAVE_FINGER_OFFSET 0x70U
#define GFPIA_IRQ_SAVE_GROUP_OFFSET 0x80U
#define GFPIA_IRQ_SAVE_FINGER_OFFSET 0x84U
/*
 * Pre-enrol. gf_hal_common_pre_enroll() clears the HAL's enrolment count and
 * sends this before any enrolment. It tries send_hmac_key() first but carries
 * on whether or not that works, so a system with no gatekeeper still gets
 * this far. The challenge it returns is what a real hw_auth_token would have
 * to be signed over.
 */
#define GFPIA_1006_PAYLOAD_SIZE 0x78U
#define GFPIA_PRE_ENROLL_CHALLENGE_OFFSET 0x70U
/*
 * Enrol. gf_hal_common_enroll() writes the group, a dump flag and a 69-byte
 * authentication token, and nothing else:
 *
 *   21690: str  w24, [x0, #108]   ; group
 *   216a0: strb w0,  [x19, #116]  ; dump flag
 *   216c4..216e0                  ; 69 bytes from 0x76
 *
 * Those 69 bytes are Android's hw_auth_token: a version byte, the challenge
 * pre-enrol returned, a user and authenticator id, a big-endian authenticator
 * type and timestamp, and a 32-byte HMAC. Without a gatekeeper there is no
 * key to sign with, so the HMAC goes in as zeroes and the TA decides.
 */
#define GFPIA_1007_PAYLOAD_SIZE 0xbcU
#define GFPIA_ENROLL_GROUP_OFFSET 0x6cU
#define GFPIA_ENROLL_DUMP_OFFSET 0x74U
#define GFPIA_ENROLL_TOKEN_OFFSET 0x76U
#define GFPIA_AUTH_TOKEN_SIZE 69U
/*
 * Authenticate. gf_hal_common_authenticate() writes a group, a 64-bit
 * operation identifier and a word of all ones, and nothing else:
 *
 *   21b30: str w21, [x0, #108]   ; group
 *   21b38: str x22, [x0, #112]   ; operation id
 *   21b48: str w9,  [x0, #120]   ; -1
 *
 * Unlike pre-enrol it refuses to send at all unless send_hmac_key() worked,
 * so whether the TA itself insists on that key is only answerable by asking
 * it directly.
 */
#define GFPIA_1010_PAYLOAD_SIZE 0x80U
#define GFPIA_AUTH_GROUP_OFFSET 0x6cU
#define GFPIA_AUTH_OPERATION_OFFSET 0x70U
#define GFPIA_AUTH_SENTINEL_OFFSET 0x78U
/* irq_image_enroll_or_authenticate() treats operation 0 as enrolment. */
#define GFPIA_IRQ_OPERATION_ENROL UINT32_C(0)
/* An enrolment counts down at 0x88 and is finished when it reaches zero. */
#define GFPIA_IRQ_TYPE_IMAGE UINT32_C(0x80)
/*
 * Command class. The HAL sends its ordinary commands as class 1 and every
 * factory-test command, including the untrusted enrolment path, as class 3.
 */
#define GFPIA_CLASS_NORMAL UINT32_C(1)
#define GFPIA_CLASS_TEST UINT32_C(3)
#define GFPIA_MODEL_LOGICAL_SIZE 0x124ff4U
#define GFPIA_MODEL_CHUNK_SIZE 0x7cf9cU
#define GFPIA_MODEL_REMAINDER_SIZE 0x2b0bcU
#define GFPIA_MODEL_CHUNK_OFFSET 0x7d008U
#define GFPIA_MODEL_TOTAL_OFFSET 0x7d00cU
#define GFPIA_MODEL_COMMAND_OFFSET 0x7d010U
#define GFPIA_MODEL_COMMAND UINT32_C(1111)
#define GFPIA_MODEL_CHUNK_COUNT 3U
#define GFPIA_MODEL_DATA_OFFSET 0x70U
#define GFPIA_ASP_MODEL_SIZE 0x4b540U
#define GFPIA_ASP_MODEL_SIZE_OFFSET 0x1248b8U
#define GFPIA_PALM_KIND_OFFSET 0x6cU
#define GFPIA_PALM_MODEL_SIZE 0x48c88U
#define GFPIA_PALM_MODEL_SIZE_OFFSET 0x124ff0U
#define GFPIA_PALM_MODEL_WORDS UINT32_C(0x12322)
#define GFPIA_PIANO_INIT_STEP_COUNT 9U
#define GFPIA_PIANO_ASP_FIRST_STEP 2U
#define GFPIA_PIANO_PALM_FIRST_STEP 5U
#define GFPIA_PIANO_1005_STEP 8U
#define GFPIA_PIANO_ACTIVE_GROUP_STEP 9U
#define GFPIA_PIANO_ACTIVE_GROUP_STEP_COUNT 10U
#define GFPIA_PIANO_ENROLL_PROBE_STEP 10U
#define GFPIA_PIANO_MAX_STEP_COUNT 11U
#define GFPIA_ACTIVE_GROUP_GID_OFFSET 0x6cU
#define GFPIA_ACTIVE_GROUP_PATH_OFFSET 0x70U
#define GFPIA_ACTIVE_GROUP_PATH_SIZE 0x200U
#define GFPIA_ACTIVE_GROUP_PATH "/data/vendor_de/0/fpdata"
#define GFPIA_HMAC_TOKEN UINT32_C(11)
#define GFPIA_HMAC_CLASS UINT32_C(2)
#define KEYMASTER_APP_NAME "keymaster64"
#define KEYMASTER_HMAC_REQUEST_SIZE 8U
#define KEYMASTER_HMAC_RESPONSE_SIZE 0x100U
#define KEYMASTER_SERVICE_HMAC_RESPONSE_CAPACITY \
	(KEYMASTER_SHARED_BUFFER_SIZE - KEYMASTER_HMAC_REQUEST_SIZE)
#define KEYMASTER_HMAC_COMMAND UINT32_C(0x205)
#define KEYMASTER_HMAC_SELECTOR UINT32_C(2)
#define KEYMASTER_HMAC_OFFSET_OFFSET 4U
#define KEYMASTER_HMAC_LENGTH_OFFSET 8U
#define KEYMASTER_HMAC_HEADER_SIZE 12U

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

struct qtee_object {
	uint64_t id;
	uint64_t flags;
};

struct blob {
	uint8_t *data;
	size_t size;
};

struct qtee_shared_memory {
	uint8_t *data;
	size_t size;
	int32_t id;
	int fd;
};

struct keymaster_service {
	struct qtee_object app_client;
	struct qtee_object opener;
	struct qtee_object hal;
};

struct keymaster_hmac_parameters {
	uint8_t seed[KEYMASTER_HMAC_VALUE_SIZE];
	uint8_t nonce[KEYMASTER_HMAC_VALUE_SIZE];
};

static void secure_clear(void *data, size_t size);
static void secure_free_blob(struct blob *blob);
static uint32_t read_le32(const uint8_t *data);
static void write_le32(uint8_t *data, uint32_t value);

enum gfpia_model_kind {
	GFPIA_MODEL_NONE,
	GFPIA_MODEL_ASP,
	GFPIA_MODEL_PALM,
};

struct gfpia_step {
	struct blob request;
	struct blob request_output;
	struct blob response;
	struct blob payload;
	struct qtee_shared_memory shared_payload;
	const char *response_path;
	const char *payload_output_path;
	const char *request_output_path;
	int response_fd;
	int payload_output_fd;
	int request_output_fd;
	bool outputs_written;
	const char *label;
	uint32_t command;
	uint32_t command_class;
	uint32_t expected_token;
	uint32_t expected_sequence;
	size_t payload_size;
	enum gfpia_model_kind model_kind;
	uint8_t model_chunk;
};

struct gfpia_piano_step_spec {
	const char *stem;
	const char *label;
	uint32_t command;
	uint32_t command_class;
	size_t payload_size;
	uint32_t token;
	uint32_t sequence;
	enum gfpia_model_kind model_kind;
	uint8_t model_chunk;
};

struct gfpia_piano_step_paths {
	char request[PATH_MAX];
	char payload[PATH_MAX];
	char response[PATH_MAX];
	char payload_output[PATH_MAX];
	char request_output[PATH_MAX];
};

_Static_assert(GFPIA_COMMON_PAYLOAD_SIZE + GFPIA_MODEL_CHUNK_SIZE ==
	       GFPIA_MODEL_CHUNK_OFFSET,
	       "model data must end at the chunk-index field");
_Static_assert(GFPIA_MODEL_COMMAND_OFFSET + sizeof(uint32_t) ==
	       GFPIA_1113_PAYLOAD_SIZE,
	       "model metadata must end at the payload boundary");
_Static_assert(2 * GFPIA_MODEL_CHUNK_SIZE + GFPIA_MODEL_REMAINDER_SIZE ==
	       GFPIA_MODEL_LOGICAL_SIZE,
	       "three model slices must cover the logical model");
_Static_assert(GFPIA_PALM_MODEL_SIZE_OFFSET + sizeof(uint32_t) ==
	       GFPIA_MODEL_LOGICAL_SIZE,
	       "palm word count must end the logical model");
_Static_assert(sizeof(GFPIA_ACTIVE_GROUP_PATH) <= GFPIA_ACTIVE_GROUP_PATH_SIZE,
	       "active-group path must include a terminating NUL");
_Static_assert(GFPIA_ACTIVE_GROUP_PATH_OFFSET +
	       GFPIA_ACTIVE_GROUP_PATH_SIZE == GFPIA_1014_PAYLOAD_SIZE,
	       "active-group path must end at the payload boundary");
_Static_assert(KEYMASTER_HMAC_RESPONSE_SIZE == GFPIA_109_PAYLOAD_SIZE,
	       "command 109 must carry the complete Keymaster response");
_Static_assert(KEYMASTER_HMAC_REQUEST_SIZE % sizeof(uint32_t) == 0,
	       "private-HMAC request must not require service alignment padding");
_Static_assert(KEYMASTER_SERVICE_HMAC_RESPONSE_CAPACITY == 0x9ff8U,
	       "private-HMAC service output capacity must remain 0x9ff8 bytes");
_Static_assert(KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE ==
	       9U + KEYMASTER_HMAC_RECORD_SIZE,
	       "get-shared-HMAC CBOR size must match its fixed schema");
_Static_assert(KEYMASTER_GET_SHARED_HMAC_SEED_OFFSET +
	       KEYMASTER_HMAC_VALUE_SIZE ==
	       KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET,
	       "get-shared-HMAC seed must end at the nonce label");
_Static_assert(KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET + 4U ==
	       KEYMASTER_GET_SHARED_HMAC_NONCE_OFFSET,
	       "get-shared-HMAC nonce must follow its four-byte field header");
_Static_assert(KEYMASTER_GET_SHARED_HMAC_NONCE_OFFSET +
	       KEYMASTER_HMAC_VALUE_SIZE == KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE,
	       "get-shared-HMAC nonce must end at the CBOR boundary");
_Static_assert(KEYMASTER_COMPUTE_SHARED_HMAC_CBOR_SIZE ==
	       5U + KEYMASTER_HMAC_RECORD_SIZE,
	       "compute-shared-HMAC CBOR size must match its fixed schema");
_Static_assert(KEYMASTER_COMPUTE_SHARED_HMAC_REQUEST_SIZE ==
	       sizeof(uint32_t) + KEYMASTER_COMPUTE_SHARED_HMAC_CBOR_SIZE,
	       "compute-shared-HMAC request size must include its command");
_Static_assert(KEYMASTER_COMPUTE_SHARED_HMAC_RECORD_OFFSET +
	       KEYMASTER_HMAC_VALUE_SIZE ==
	       KEYMASTER_COMPUTE_SHARED_HMAC_NONCE_OFFSET,
	       "compute-shared-HMAC nonce must immediately follow its seed");
_Static_assert(KEYMASTER_COMPUTE_SHARED_HMAC_NONCE_OFFSET +
	       KEYMASTER_HMAC_VALUE_SIZE ==
	       KEYMASTER_COMPUTE_SHARED_HMAC_REQUEST_SIZE,
	       "compute-shared-HMAC nonce must end at the request boundary");
_Static_assert(KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE ==
	       5U + KEYMASTER_HMAC_VALUE_SIZE,
	       "compute-shared-HMAC response must contain one 32-byte check");
_Static_assert(KEYMASTER_COMPUTE_SHARED_HMAC_CHECK_OFFSET +
	       KEYMASTER_HMAC_VALUE_SIZE ==
	       KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE,
	       "sharing check must end at the compute-response CBOR boundary");

static volatile sig_atomic_t stop_requested;

static void handle_signal(int signo)
{
	(void)signo;
	stop_requested = 1;
}

static int report_errno(const char *what)
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

static int object_invoke(int fd, struct qtee_object object, uint32_t op,
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

static int object_release(int fd, struct qtee_object *object)
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

static int shared_memory_alloc(int tee_fd, size_t size,
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

static void shared_memory_release(struct qtee_shared_memory *memory)
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

static int find_qcomtee_device(char *path, size_t path_size)
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

static int get_client_env(int fd, struct qtee_object *client_env)
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

static int client_env_open(int fd, struct qtee_object client_env, uint32_t uid,
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

static int app_client_get_app_object(int fd, struct qtee_object app_client,
				     const char *app_name,
				     struct qtee_object *opener)
{
	struct tee_ioctl_param params[] = {
		ubuf_input(app_name, strlen(app_name)),
		objref_output(),
	};
	uint32_t secure_result = 0;
	int ret;

	ret = object_invoke(fd, app_client, 0, params, ARRAY_SIZE(params),
			    &secure_result);
	if (ret)
		return ret;
	if (secure_result) {
		fprintf(stderr,
			"IAppClient.getAppObject(%s) failed in QTEE: %" PRIu32
			"\n",
			app_name, secure_result);
		return -EREMOTEIO;
	}

	return object_from_output(&params[1], opener);
}

static int opener_open(int fd, struct qtee_object opener, uint32_t service_id,
		       struct qtee_object *service)
{
	struct tee_ioctl_param params[] = {
		ubuf_input(&service_id, sizeof(service_id)),
		objref_output(),
	};
	uint32_t secure_result = 0;
	int ret;

	ret = object_invoke(fd, opener, 0, params, ARRAY_SIZE(params),
			    &secure_result);
	if (ret)
		return ret;
	if (secure_result) {
		fprintf(stderr,
			"IOpener.open(service ID %" PRIu32
			") failed in QTEE: %" PRIu32 "\n",
			service_id, secure_result);
		return -EREMOTEIO;
	}

	return object_from_output(&params[1], service);
}

static int keymaster_send_service_command(int fd,
					  struct qtee_object keymaster,
					  const void *request,
					  size_t request_size,
					  struct blob *response)
{
	struct tee_ioctl_param params[2];
	uint8_t *buffer;
	uint32_t secure_result = 0;
	size_t response_capacity;
	size_t response_offset;
	int ret;

	if (!request || !request_size || !response || response->data ||
	    response->size ||
	    request_size >= KEYMASTER_SHARED_BUFFER_SIZE)
		return -EINVAL;

	buffer = calloc(1, KEYMASTER_SHARED_BUFFER_SIZE);
	if (!buffer)
		return -ENOMEM;
	memcpy(buffer, request, request_size);
	/* KeymasterUtils starts the output at the next four-byte boundary. */
	response_offset = (request_size + 3U) & ~(size_t)3U;
	response_capacity = KEYMASTER_SHARED_BUFFER_SIZE - response_offset;
	params[0] = ubuf_input(buffer, request_size);
	params[1] = ubuf_output(buffer + response_offset, response_capacity);

	ret = object_invoke(fd, keymaster, KEYMASTER_OBJECT_OP_SEND_COMMAND,
			    params, ARRAY_SIZE(params), &secure_result);
	if (ret)
		goto out;
	if (secure_result) {
		fprintf(stderr, "IKMHal.sendCmd failed in QTEE: %" PRIu32 "\n",
			secure_result);
		ret = -EREMOTEIO;
		goto out;
	}
	if (params[1].b > response_capacity) {
		ret = -EPROTO;
		goto out;
	}
	if (!params[1].b)
		goto out;

	response->data = malloc(params[1].b);
	if (!response->data) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(response->data, buffer + response_offset, params[1].b);
	response->size = params[1].b;

out:
	secure_clear(buffer, KEYMASTER_SHARED_BUFFER_SIZE);
	free(buffer);
	return ret;
}

static int keymaster_service_open(int fd, struct qtee_object client_env,
				  struct keymaster_service *service)
{
	*service = (struct keymaster_service) {
		.app_client = { .id = TEE_OBJREF_NULL },
		.opener = { .id = TEE_OBJREF_NULL },
		.hal = { .id = TEE_OBJREF_NULL },
	};

	int ret = client_env_open(fd, client_env, KEYMASTER_APP_CLIENT_UID,
				  &service->app_client);

	if (ret)
		return ret;
	fprintf(stdout, "Keymaster app-client object: %" PRIu64 "\n",
		service->app_client.id);

	ret = app_client_get_app_object(fd, service->app_client,
					KEYMASTER_APP_NAME, &service->opener);
	if (ret)
		return ret;
	fprintf(stdout, "Keymaster opener object: %" PRIu64 "\n",
		service->opener.id);

	ret = opener_open(fd, service->opener, KEYMASTER_HAL_SERVICE_ID,
			  &service->hal);
	if (ret)
		return ret;
	fprintf(stdout, "Keymaster service object: %" PRIu64 "\n",
		service->hal.id);
	return 0;
}

static int keymaster_service_release(int fd,
				     struct keymaster_service *service)
{
	int ret = object_release(fd, &service->hal);
	int cleanup_ret = object_release(fd, &service->opener);

	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	cleanup_ret = object_release(fd, &service->app_client);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	return ret;
}

static int keymaster_service_get_version(int fd, struct qtee_object keymaster)
{
	uint32_t request = KEYMASTER_GET_VERSION_COMMAND;
	struct blob response = { 0 };
	uint32_t status;
	int ret;

	ret = keymaster_send_service_command(fd, keymaster, &request,
					     KEYMASTER_GET_VERSION_REQUEST_SIZE,
					     &response);
	if (ret)
		goto out;
	if (response.size < sizeof(status)) {
		fprintf(stderr,
			"Keymaster get-version returned only %zu status bytes\n",
			response.size);
		ret = -EPROTO;
		goto out;
	}

	status = read_le32(response.data);
	if (status) {
		fprintf(stderr,
			"Keymaster get-version returned status 0x%08" PRIx32
			" (%" PRId32 ")\n",
			status, (int32_t)status);
		ret = -EREMOTEIO;
		goto out;
	}
	if (response.size < KEYMASTER_GET_VERSION_RESPONSE_SIZE) {
		fprintf(stderr,
			"Keymaster get-version returned only %zu bytes\n",
			response.size);
		ret = -EPROTO;
		goto out;
	}

	fprintf(stdout,
		"Keymaster versions: major=%" PRIu32
		", minor=%" PRIu32 ", TA major=%" PRIu32
		", TA minor=%" PRIu32 "\n",
		read_le32(response.data + 4), read_le32(response.data + 8),
		read_le32(response.data + 12), read_le32(response.data + 16));

out:
	secure_free_blob(&response);
	return ret;
}

static int keymaster_service_set_version(int fd, struct qtee_object keymaster)
{
	uint8_t request[KEYMASTER_SET_VERSION_REQUEST_SIZE] = { 0 };
	struct blob response = { 0 };
	uint32_t status;
	int ret;

	write_le32(request, KEYMASTER_SET_VERSION_COMMAND);
	write_le32(request + 4, KEYMASTER_CLIENT_MAJOR_VERSION);
	write_le32(request + 8, KEYMASTER_CLIENT_MINOR_VERSION);
	write_le32(request + 12, KEYMASTER_CLIENT_TA_MAJOR_VERSION);
	write_le32(request + 16, KEYMASTER_CLIENT_TA_MINOR_VERSION);

	ret = keymaster_send_service_command(fd, keymaster, request,
					     sizeof(request), &response);
	if (ret)
		goto out;
	if (response.size < sizeof(status)) {
		fprintf(stderr,
			"Keymaster set-version returned only %zu status bytes\n",
			response.size);
		ret = -EPROTO;
		goto out;
	}

	status = read_le32(response.data);
	if (status) {
		fprintf(stderr,
			"Keymaster set-version returned status 0x%08" PRIx32
			" (%" PRId32 ")\n",
			status, (int32_t)status);
		ret = -EREMOTEIO;
		goto out;
	}
	fprintf(stdout,
		"Keymaster set-version accepted client versions %" PRIu32 ".%"
		PRIu32 " / TA %" PRIu32 ".%" PRIu32 "\n",
		KEYMASTER_CLIENT_MAJOR_VERSION, KEYMASTER_CLIENT_MINOR_VERSION,
		KEYMASTER_CLIENT_TA_MAJOR_VERSION,
		KEYMASTER_CLIENT_TA_MINOR_VERSION);

out:
	secure_free_blob(&response);
	secure_clear(request, sizeof(request));
	return ret;
}

static void build_keymaster_keymint_version_request(uint8_t *request)
{
	/* KeymasterSerialize::serializeInteger(300): CBOR map { 11: 300 }. */
	write_le32(request, KEYMASTER_KEYMINT_SET_VERSION_COMMAND);
	request[4] = 0xa1;
	request[5] = 0x0b;
	request[6] = 0x19;
	request[7] = 0x01;
	request[8] = 0x2c;
}

static int keymaster_service_set_keymint_version(
			int fd, struct qtee_object keymaster)
{
	uint8_t request[KEYMASTER_KEYMINT_SET_VERSION_REQUEST_SIZE] = { 0 };
	struct blob response = { 0 };
	uint32_t payload_size;
	uint32_t status;
	int ret;

	build_keymaster_keymint_version_request(request);
	ret = keymaster_send_service_command(fd, keymaster, request,
					     sizeof(request), &response);
	if (ret)
		goto out;
	if (response.size < 2U * sizeof(uint32_t)) {
		fprintf(stderr,
			"KeyMint set-version returned only %zu bytes\n",
			response.size);
		ret = -EPROTO;
		goto out;
	}

	status = read_le32(response.data);
	if (status) {
		fprintf(stderr,
			"KeyMint set-version returned status 0x%08" PRIx32
			" (%" PRId32 ")\n",
			status, (int32_t)status);
		ret = -EREMOTEIO;
		goto out;
	}

	payload_size = read_le32(response.data + sizeof(uint32_t));
	if (payload_size > response.size - 2U * sizeof(uint32_t)) {
		fprintf(stderr,
			"KeyMint set-version returned invalid payload size %" PRIu32
			" in %zu bytes\n",
			payload_size, response.size);
		ret = -EPROTO;
		goto out;
	}

	fprintf(stdout,
		"KeyMint accepted serialized version %" PRIu32
		" (bounded response payload %" PRIu32 " bytes)\n",
		KEYMASTER_KEYMINT_SET_VERSION_VALUE, payload_size);

out:
	secure_free_blob(&response);
	secure_clear(request, sizeof(request));
	return ret;
}

static void build_keymaster_date_support_request(uint8_t *request)
{
	memset(request, 0, KEYMASTER_GET_DATE_SUPPORT_REQUEST_SIZE);
	write_le32(request, KEYMASTER_GET_DATE_SUPPORT_COMMAND);
}

static int validate_keymaster_date_support_response(
				const struct blob *response, bool require_full_date)
{
	uint32_t status;

	if (!response || !response->data || response->size < sizeof(status)) {
		fprintf(stderr,
			"Keymaster date-support query returned a truncated status\n");
		return -EPROTO;
	}

	status = read_le32(response->data);
	if (!status) {
		fprintf(stdout,
			"Keymaster reports full-date patchlevel support\n");
		return 0;
	}
	if ((int32_t)status == -40) {
		fprintf(stdout,
			"Keymaster requires YYYYMM patchlevels (status -40)\n");
		if (require_full_date) {
			fprintf(stderr,
				"full-date patchlevel support is required for this probe\n");
			return -EOPNOTSUPP;
		}
		return 0;
	}

	fprintf(stderr,
		"Keymaster date-support query returned status 0x%08" PRIx32
		" (%" PRId32 ")\n",
		status, (int32_t)status);
	return -EREMOTEIO;
}

static int keymaster_service_get_date_support(
				int fd, struct qtee_object keymaster,
				bool require_full_date)
{
	uint8_t request[KEYMASTER_GET_DATE_SUPPORT_REQUEST_SIZE];
	struct blob response = { 0 };
	int ret;

	build_keymaster_date_support_request(request);
	ret = keymaster_send_service_command(fd, keymaster, request,
							     sizeof(request), &response);
	if (ret)
		goto out;
	ret = validate_keymaster_date_support_response(&response,
						       require_full_date);

out:
	secure_free_blob(&response);
	secure_clear(request, sizeof(request));
	return ret;
}

static void build_keymaster_configure_request(uint8_t *request)
{
	static const uint8_t cbor[] = {
		0xa4, 0x16, 0x03,
		0x1a, 0x30, 0x00, 0x02, 0xc1,
		0x1a, 0x00, 0x02, 0x71, 0x00,
		0x1a, 0x30, 0x00, 0x02, 0xc2,
		0x1a, 0x01, 0x35, 0x27, 0x5d,
		0x1a, 0x30, 0x00, 0x02, 0xce,
		0x1a, 0x01, 0x35, 0x25, 0x69,
	};

	_Static_assert(sizeof(cbor) + sizeof(uint32_t) ==
		       KEYMASTER_CONFIGURE_REQUEST_SIZE,
		       "fixed Keymaster configure request size must match");

	write_le32(request, KEYMASTER_CONFIGURE_COMMAND);
	memcpy(request + sizeof(uint32_t), cbor, sizeof(cbor));
}

static int keymaster_service_configure(int fd, struct qtee_object keymaster)
{
	uint8_t request[KEYMASTER_CONFIGURE_REQUEST_SIZE] = { 0 };
	struct blob response = { 0 };
	uint32_t payload_size;
	uint32_t status;
	int ret;

	build_keymaster_configure_request(request);
	ret = keymaster_send_service_command(fd, keymaster, request,
						     sizeof(request), &response);
	if (ret)
		goto out;
	if (response.size < 2U * sizeof(uint32_t)) {
		fprintf(stderr,
			"Keymaster configure returned only %zu bytes\n",
			response.size);
		ret = -EPROTO;
		goto out;
	}

	status = read_le32(response.data);
	if (status) {
		fprintf(stderr,
			"Keymaster configure returned status 0x%08" PRIx32
			" (%" PRId32 ")\n",
			status, (int32_t)status);
		ret = -EREMOTEIO;
		goto out;
	}

	payload_size = read_le32(response.data + sizeof(uint32_t));
	if (payload_size > response.size - 2U * sizeof(uint32_t)) {
		fprintf(stderr,
			"Keymaster configure returned invalid payload size %" PRIu32
			" in %zu bytes\n",
			payload_size, response.size);
		ret = -EPROTO;
		goto out;
	}

	fprintf(stdout,
		"Keymaster accepted OS version %" PRIu32
		", OS patchlevel %" PRIu32
		", and vendor patchlevel %" PRIu32
		" (bounded response payload %" PRIu32 " bytes)\n",
		KEYMASTER_OS_VERSION, KEYMASTER_OS_PATCHLEVEL,
		KEYMASTER_VENDOR_PATCHLEVEL, payload_size);

out:
	secure_free_blob(&response);
	secure_clear(request, sizeof(request));
	return ret;
}

static int keymaster_success_payload(const struct blob *response,
				     uint32_t command,
				     const uint8_t **payload,
				     size_t *payload_size)
{
	uint32_t declared_size;
	uint32_t status;

	if (!payload || !payload_size)
		return -EINVAL;
	*payload = NULL;
	*payload_size = 0;

	if (!response || !response->data || response->size < sizeof(status)) {
		fprintf(stderr,
			"Keymaster command 0x%04" PRIx32
			" returned a truncated status\n", command);
		return -EPROTO;
	}

	status = read_le32(response->data);
	if (status) {
		fprintf(stderr,
			"Keymaster command 0x%04" PRIx32
			" returned status 0x%08" PRIx32 " (%" PRId32 ")\n",
			command, status, (int32_t)status);
		return -EREMOTEIO;
	}

	if (response->size < KEYMASTER_RESPONSE_HEADER_SIZE) {
		fprintf(stderr,
			"Keymaster command 0x%04" PRIx32
			" returned a truncated response envelope\n", command);
		return -EPROTO;
	}

	declared_size = read_le32(response->data + sizeof(uint32_t));
	if ((size_t)declared_size >
	    response->size - KEYMASTER_RESPONSE_HEADER_SIZE) {
		fprintf(stderr,
			"Keymaster command 0x%04" PRIx32
			" returned an out-of-bounds payload length\n", command);
		return -EPROTO;
	}

	*payload = response->data + KEYMASTER_RESPONSE_HEADER_SIZE;
	*payload_size = declared_size;
	return 0;
}

static void build_keymaster_get_shared_hmac_request(uint8_t *request)
{
	memset(request, 0, KEYMASTER_GET_SHARED_HMAC_REQUEST_SIZE);
	write_le32(request, KEYMASTER_GET_SHARED_HMAC_COMMAND);
}

static int decode_keymaster_get_shared_hmac_response(
				const struct blob *response,
				struct keymaster_hmac_parameters *parameters)
{
	static const uint8_t first_field[] = {
		0xa2, 0x18, 0x29, 0x58, 0x20,
	};
	static const uint8_t second_field[] = {
		0x18, 0x2a, 0x58, 0x20,
	};
	const uint8_t *payload;
	size_t payload_size;
	int ret;

	if (!parameters)
		return -EINVAL;
	secure_clear(parameters, sizeof(*parameters));

	ret = keymaster_success_payload(response,
					KEYMASTER_GET_SHARED_HMAC_COMMAND,
					&payload, &payload_size);
	if (ret)
		return ret;
	if (payload_size != KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE) {
		fprintf(stderr,
			"Keymaster get-shared-HMAC returned %zu CBOR bytes, expected %u\n",
			payload_size, KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE);
		return -EPROTO;
	}
	if (memcmp(payload, first_field, sizeof(first_field)) ||
	    memcmp(payload + KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET,
		   second_field, sizeof(second_field))) {
		fprintf(stderr,
			"Keymaster get-shared-HMAC returned non-canonical CBOR\n");
		return -EPROTO;
	}

	memcpy(parameters->seed,
	       payload + KEYMASTER_GET_SHARED_HMAC_SEED_OFFSET,
	       sizeof(parameters->seed));
	memcpy(parameters->nonce,
	       payload + KEYMASTER_GET_SHARED_HMAC_NONCE_OFFSET,
	       sizeof(parameters->nonce));
	return 0;
}

static void build_keymaster_compute_shared_hmac_request(
				uint8_t *request,
				const struct keymaster_hmac_parameters *parameters)
{
	static const uint8_t cbor_prefix[] = {
		0xa1, 0x18, 0x2b, 0x58, 0x40,
	};

	memset(request, 0, KEYMASTER_COMPUTE_SHARED_HMAC_REQUEST_SIZE);
	write_le32(request, KEYMASTER_COMPUTE_SHARED_HMAC_COMMAND);
	memcpy(request + sizeof(uint32_t), cbor_prefix, sizeof(cbor_prefix));
	memcpy(request + KEYMASTER_COMPUTE_SHARED_HMAC_RECORD_OFFSET,
	       parameters->seed, sizeof(parameters->seed));
	memcpy(request + KEYMASTER_COMPUTE_SHARED_HMAC_NONCE_OFFSET,
	       parameters->nonce, sizeof(parameters->nonce));
}

static int validate_keymaster_compute_shared_hmac_response(
				const struct blob *response)
{
	static const uint8_t expected_prefix[] = {
		0xa1, 0x18, 0x2c, 0x58, 0x20,
	};
	const uint8_t *payload;
	size_t payload_size;
	int ret;

	ret = keymaster_success_payload(response,
					KEYMASTER_COMPUTE_SHARED_HMAC_COMMAND,
					&payload, &payload_size);
	if (ret)
		return ret;
	if (payload_size != KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE) {
		fprintf(stderr,
			"Keymaster compute-shared-HMAC returned %zu CBOR bytes, expected %u\n",
			payload_size,
			KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE);
		return -EPROTO;
	}
	if (memcmp(payload, expected_prefix, sizeof(expected_prefix))) {
		fprintf(stderr,
			"Keymaster compute-shared-HMAC returned non-canonical CBOR\n");
		return -EPROTO;
	}

	return 0;
}

static int disable_keymaster_hmac_dumps(void)
{
	const struct rlimit no_core = {
		.rlim_cur = 0,
		.rlim_max = 0,
	};

	if (setrlimit(RLIMIT_CORE, &no_core) < 0)
		return report_errno("disable shared-HMAC core dumps");
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
		return report_errno("disable shared-HMAC process dumps");
	return 0;
}

static int keymaster_service_agree_shared_hmac(
				int fd, struct qtee_object keymaster)
{
	uint8_t get_request[KEYMASTER_GET_SHARED_HMAC_REQUEST_SIZE] = { 0 };
	uint8_t compute_request[KEYMASTER_COMPUTE_SHARED_HMAC_REQUEST_SIZE] = { 0 };
	struct keymaster_hmac_parameters parameters = { 0 };
	struct blob get_response = { 0 };
	struct blob compute_response = { 0 };
	int ret;

	ret = disable_keymaster_hmac_dumps();
	if (ret)
		goto out;

	build_keymaster_get_shared_hmac_request(get_request);
	ret = keymaster_send_service_command(fd, keymaster, get_request,
					     sizeof(get_request), &get_response);
	if (ret)
		goto out;
	ret = decode_keymaster_get_shared_hmac_response(&get_response,
							       &parameters);
	secure_free_blob(&get_response);
	if (ret)
		goto out;

	build_keymaster_compute_shared_hmac_request(compute_request, &parameters);
	ret = keymaster_send_service_command(fd, keymaster, compute_request,
					     sizeof(compute_request),
					     &compute_response);
	secure_clear(compute_request, sizeof(compute_request));
	secure_clear(&parameters, sizeof(parameters));
	if (ret)
		goto out;

	ret = validate_keymaster_compute_shared_hmac_response(&compute_response);
	secure_free_blob(&compute_response);

out:
	secure_free_blob(&get_response);
	secure_free_blob(&compute_response);
	secure_clear(get_request, sizeof(get_request));
	secure_clear(compute_request, sizeof(compute_request));
	secure_clear(&parameters, sizeof(parameters));
	return ret;
}

static int probe_keymaster_service(int fd, struct qtee_object client_env,
				   bool set_version)
{
	struct keymaster_service service;
	int cleanup_ret;
	int ret;

	ret = keymaster_service_open(fd, client_env, &service);
	if (ret)
		goto out;
	ret = keymaster_service_get_version(fd, service.hal);
	if (!ret && set_version)
		ret = keymaster_service_set_version(fd, service.hal);

out:
	cleanup_ret = keymaster_service_release(fd, &service);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	return ret;
}

static int probe_keymaster_service_keymint_version(
			int fd, struct qtee_object client_env)
{
	struct keymaster_service service;
	int cleanup_ret;
	int ret;

	ret = keymaster_service_open(fd, client_env, &service);
	if (ret)
		goto out;
	ret = keymaster_service_get_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_keymint_version(fd, service.hal);

out:
	cleanup_ret = keymaster_service_release(fd, &service);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	return ret;
}

static int probe_keymaster_service_date_support(
			int fd, struct qtee_object client_env)
{
	struct keymaster_service service;
	int cleanup_ret;
	int ret;

	ret = keymaster_service_open(fd, client_env, &service);
	if (ret)
		goto out;
	ret = keymaster_service_get_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_get_date_support(fd, service.hal, false);

out:
	cleanup_ret = keymaster_service_release(fd, &service);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	return ret;
}

static int probe_keymaster_service_configure(
			int fd, struct qtee_object client_env)
{
	struct keymaster_service service;
	int cleanup_ret;
	int ret;

	ret = keymaster_service_open(fd, client_env, &service);
	if (ret)
		goto out;
	ret = keymaster_service_get_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_keymint_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_configure(fd, service.hal);

out:
	cleanup_ret = keymaster_service_release(fd, &service);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	return ret;
}

static int probe_keymaster_service_shared_hmac(
				int fd, struct qtee_object client_env)
{
	struct keymaster_service service;
	int cleanup_ret;
	int ret;

	ret = keymaster_service_open(fd, client_env, &service);
	if (ret)
		goto out;
	ret = keymaster_service_get_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_get_date_support(fd, service.hal, true);
	if (ret)
		goto out;
	ret = keymaster_service_set_keymint_version(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_configure(fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_agree_shared_hmac(fd, service.hal);

out:
	cleanup_ret = keymaster_service_release(fd, &service);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	if (!ret)
		fprintf(stdout,
			"Keymaster single-instance shared-HMAC agreement completed\n");
	return ret;
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

static int read_file(const char *path, size_t maximum, struct blob *blob)
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

static int write_open_file(int fd, const char *path, const struct blob *blob)
{
	ssize_t count;
	size_t offset = 0;

	if (ftruncate(fd, 0) < 0)
		return report_errno(path);
	if (lseek(fd, 0, SEEK_SET) < 0)
		return report_errno(path);

	while (offset < blob->size) {
		count = write(fd, blob->data + offset, blob->size - offset);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			return report_errno(path);
		}
		if (!count)
			return -EIO;
		offset += (size_t)count;
	}

	if (fsync(fd) < 0) {
		return report_errno("fsync output");
	}

	return 0;
}

static int write_file(const char *path, const struct blob *blob)
{
	int ret;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return report_errno(path);

	ret = write_open_file(fd, path, blob);
	if (close(fd) < 0)
		return ret ? ret : report_errno(path);
	return ret;
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
static void app_unload(int fd, struct qtee_object controller)
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

static int start_app(int fd, struct qtee_object loader, const char *app_name,
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

static void secure_clear(void *data, size_t size)
{
	volatile uint8_t *byte = data;

	if (!data)
		return;
	while (size--)
		*byte++ = 0;
}

static void secure_free_blob(struct blob *blob)
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

static void secure_shared_memory_release(struct qtee_shared_memory *memory)
{
	if (memory && memory->data)
		secure_clear(memory->data, memory->size);
	shared_memory_release(memory);
}

static int send_request(int fd, struct qtee_object controller,
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

static int parse_size(const char *string, size_t *size)
{
	char *end = NULL;
	uintmax_t value;

	errno = 0;
	value = strtoumax(string, &end, 0);
	if (errno || !end || *end || !value || value > MAX_IO_BUFFER_SIZE)
		return -EINVAL;
	*size = (size_t)value;
	return 0;
}

static uint32_t read_le32(const uint8_t *data)
{
	return (uint32_t)data[0] | (uint32_t)data[1] << 8 |
	       (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
}

static uint16_t read_le16(const uint8_t *data)
{
	return (uint16_t)data[0] | (uint16_t)data[1] << 8;
}

static uint64_t read_le64(const uint8_t *data)
{
	return (uint64_t)read_le32(data) |
	       (uint64_t)read_le32(data + sizeof(uint32_t)) << 32;
}

static void write_le32(uint8_t *data, uint32_t value)
{
	data[0] = (uint8_t)value;
	data[1] = (uint8_t)(value >> 8);
	data[2] = (uint8_t)(value >> 16);
	data[3] = (uint8_t)(value >> 24);
}

static void write_le64(uint8_t *data, uint64_t value)
{
	write_le32(data, (uint32_t)value);
	write_le32(data + sizeof(uint32_t), (uint32_t)(value >> 32));
}

static bool bytes_are_zero(const uint8_t *data, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (data[i])
			return false;
	}
	return true;
}

static uint32_t read_be32(const uint8_t *data)
{
	return (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 |
	       (uint32_t)data[2] << 8 | (uint32_t)data[3];
}

static void write_be32(uint8_t *data, uint32_t value)
{
	data[0] = (uint8_t)(value >> 24);
	data[1] = (uint8_t)(value >> 16);
	data[2] = (uint8_t)(value >> 8);
	data[3] = (uint8_t)value;
}

static uint32_t rotate_right32(uint32_t value, unsigned int shift)
{
	return value >> shift | value << (32 - shift);
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
	static const uint32_t constants[64] = {
		UINT32_C(0x428a2f98), UINT32_C(0x71374491),
		UINT32_C(0xb5c0fbcf), UINT32_C(0xe9b5dba5),
		UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
		UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5),
		UINT32_C(0xd807aa98), UINT32_C(0x12835b01),
		UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
		UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe),
		UINT32_C(0x9bdc06a7), UINT32_C(0xc19bf174),
		UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
		UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc),
		UINT32_C(0x2de92c6f), UINT32_C(0x4a7484aa),
		UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
		UINT32_C(0x983e5152), UINT32_C(0xa831c66d),
		UINT32_C(0xb00327c8), UINT32_C(0xbf597fc7),
		UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
		UINT32_C(0x06ca6351), UINT32_C(0x14292967),
		UINT32_C(0x27b70a85), UINT32_C(0x2e1b2138),
		UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
		UINT32_C(0x650a7354), UINT32_C(0x766a0abb),
		UINT32_C(0x81c2c92e), UINT32_C(0x92722c85),
		UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
		UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3),
		UINT32_C(0xd192e819), UINT32_C(0xd6990624),
		UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
		UINT32_C(0x19a4c116), UINT32_C(0x1e376c08),
		UINT32_C(0x2748774c), UINT32_C(0x34b0bcb5),
		UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
		UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3),
		UINT32_C(0x748f82ee), UINT32_C(0x78a5636f),
		UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
		UINT32_C(0x90befffa), UINT32_C(0xa4506ceb),
		UINT32_C(0xbef9a3f7), UINT32_C(0xc67178f2),
	};
	uint32_t words[64];
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t f = state[5];
	uint32_t g = state[6];
	uint32_t h = state[7];
	uint32_t choice;
	uint32_t majority;
	uint32_t sigma0;
	uint32_t sigma1;
	uint32_t sum0;
	uint32_t sum1;
	uint32_t temporary1;
	uint32_t temporary2;
	size_t i;

	for (i = 0; i < 16; i++)
		words[i] = read_be32(block + i * sizeof(uint32_t));
	for (; i < ARRAY_SIZE(words); i++) {
		sigma0 = rotate_right32(words[i - 15], 7) ^
			 rotate_right32(words[i - 15], 18) ^
			 (words[i - 15] >> 3);
		sigma1 = rotate_right32(words[i - 2], 17) ^
			 rotate_right32(words[i - 2], 19) ^
			 (words[i - 2] >> 10);
		words[i] = words[i - 16] + sigma0 + words[i - 7] + sigma1;
	}

	for (i = 0; i < ARRAY_SIZE(words); i++) {
		sum1 = rotate_right32(e, 6) ^ rotate_right32(e, 11) ^
		       rotate_right32(e, 25);
		choice = (e & f) ^ (~e & g);
		temporary1 = h + sum1 + choice + constants[i] + words[i];
		sum0 = rotate_right32(a, 2) ^ rotate_right32(a, 13) ^
		       rotate_right32(a, 22);
		majority = (a & b) ^ (a & c) ^ (b & c);
		temporary2 = sum0 + majority;
		h = g;
		g = f;
		f = e;
		e = d + temporary1;
		d = c;
		c = b;
		b = a;
		a = temporary1 + temporary2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

static void sha256_digest(const uint8_t *data, size_t size, uint8_t digest[32])
{
	uint32_t state[8] = {
		UINT32_C(0x6a09e667), UINT32_C(0xbb67ae85),
		UINT32_C(0x3c6ef372), UINT32_C(0xa54ff53a),
		UINT32_C(0x510e527f), UINT32_C(0x9b05688c),
		UINT32_C(0x1f83d9ab), UINT32_C(0x5be0cd19),
	};
	uint8_t tail[128] = { 0 };
	uint64_t bit_length = (uint64_t)size * 8;
	size_t offset = 0;
	size_t tail_size;
	size_t i;

	while (size - offset >= 64) {
		sha256_transform(state, data + offset);
		offset += 64;
	}
	tail_size = size - offset;
	memcpy(tail, data + offset, tail_size);
	tail[tail_size] = 0x80;
	tail_size = tail_size < 56 ? 64 : 128;
	for (i = 0; i < sizeof(bit_length); i++)
		tail[tail_size - sizeof(bit_length) + i] =
			(uint8_t)(bit_length >> (56 - i * 8));
	sha256_transform(state, tail);
	if (tail_size == sizeof(tail))
		sha256_transform(state, tail + 64);
	for (i = 0; i < ARRAY_SIZE(state); i++)
		write_be32(digest + i * sizeof(uint32_t), state[i]);
}

static int validate_gfpia_modified(const struct blob *request,
				   const struct blob *payload,
				   size_t response_size)
{
	uint64_t patch_value;
	uint32_t declared_payload_size;

	if (request->size != GFPIA_REQUEST_SIZE) {
		fprintf(stderr, "gfpia request must be exactly 0x80 bytes\n");
		return -EINVAL;
	}
	if (response_size != GFPIA_RESPONSE_SIZE) {
		fprintf(stderr, "gfpia response must be exactly 0x40 bytes\n");
		return -EINVAL;
	}

	memcpy(&patch_value, request->data, sizeof(patch_value));
	if (patch_value) {
		fprintf(stderr,
			"gfpia request offsets 0..7 must be zero for QTEE to patch\n");
		return -EINVAL;
	}
	declared_payload_size = read_le32(request->data + 0x24);
	if (declared_payload_size != payload->size) {
		fprintf(stderr,
			"gfpia request declares 0x%" PRIx32
			" payload bytes, file has 0x%zx\n",
			declared_payload_size, payload->size);
		return -EINVAL;
	}

	return 0;
}

static int validate_gfpia_model_chunk_input(const struct gfpia_step *step)
{
	uint8_t expected_common[GFPIA_COMMON_PAYLOAD_SIZE] = { 0 };
	const uint8_t *payload = step->payload.data;

	if (step->model_kind == GFPIA_MODEL_NONE ||
	    step->model_chunk >= GFPIA_MODEL_CHUNK_COUNT) {
		fprintf(stderr, "%s has an invalid model chunk descriptor\n",
			step->label);
		return -EINVAL;
	}

	write_le32(expected_common + 0x44, step->expected_sequence);
	if (memcmp(payload, expected_common, sizeof(expected_common))) {
		fprintf(stderr, "%s has unexpected common payload fields\n",
			step->label);
		return -EINVAL;
	}
	if (payload[GFPIA_MODEL_CHUNK_OFFSET] != step->model_chunk ||
	    !bytes_are_zero(payload + GFPIA_MODEL_CHUNK_OFFSET + 1,
			       GFPIA_MODEL_TOTAL_OFFSET -
			       GFPIA_MODEL_CHUNK_OFFSET - 1)) {
		fprintf(stderr, "%s has an invalid chunk index or padding\n",
			step->label);
		return -EINVAL;
	}
	if (read_le32(payload + GFPIA_MODEL_TOTAL_OFFSET) !=
	    GFPIA_MODEL_LOGICAL_SIZE ||
	    read_le32(payload + GFPIA_MODEL_COMMAND_OFFSET) !=
	    GFPIA_MODEL_COMMAND) {
		fprintf(stderr, "%s has invalid model transport metadata\n",
			step->label);
		return -EINVAL;
	}
	if (step->model_chunk == GFPIA_MODEL_CHUNK_COUNT - 1 &&
	    !bytes_are_zero(payload + GFPIA_COMMON_PAYLOAD_SIZE +
			       GFPIA_MODEL_REMAINDER_SIZE,
			       GFPIA_MODEL_CHUNK_SIZE -
			       GFPIA_MODEL_REMAINDER_SIZE)) {
		fprintf(stderr, "%s has nonzero bytes after the final model slice\n",
			step->label);
		return -EINVAL;
	}

	return 0;
}

static int validate_gfpia_sequence_input(const struct gfpia_step *step)
{
	uint8_t expected_request[GFPIA_REQUEST_SIZE] = { 0 };
	uint8_t expected_payload[GFPIA_1000_PAYLOAD_SIZE] = { 0 };
	uint64_t request_time;
	uint32_t log_level;
	int ret;

	ret = validate_gfpia_modified(&step->request, &step->payload,
				      GFPIA_RESPONSE_SIZE);
	if (ret)
		return ret;
	if (step->payload.size != step->payload_size) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " payload must be exactly 0x%zx bytes\n",
			step->command, step->payload_size);
		return -EINVAL;
	}

	request_time = read_le64(step->request.data + 0x10);
	log_level = read_le32(step->request.data + 0x18);
	if (request_time > UINT64_C(86399999)) {
		fprintf(stderr, "gfpia request time is not milliseconds since midnight\n");
		return -EINVAL;
	}
	if (log_level > 4U) {
		fprintf(stderr, "gfpia log level must be in the range 0..4\n");
		return -EINVAL;
	}

	if (step->command == GFPIA_1000_COMMAND) {
		if (step->model_kind != GFPIA_MODEL_NONE)
			return -EINVAL;
		write_le32(expected_payload + 0x278, 4);
	} else if (step->command == GFPIA_1001_COMMAND) {
		if (step->model_kind != GFPIA_MODEL_NONE)
			return -EINVAL;
	} else if (step->command == GFPIA_1005_COMMAND) {
		if (step->model_kind != GFPIA_MODEL_NONE)
			return -EINVAL;
	} else if (step->command == GFPIA_1014_COMMAND) {
		if (step->model_kind != GFPIA_MODEL_NONE)
			return -EINVAL;
	} else if (step->command == GFPIA_1113_COMMAND) {
		if (step->payload_size != GFPIA_1113_PAYLOAD_SIZE)
			return -EINVAL;
	} else if (step->command == GFPIA_1060_COMMAND) {
		/*
		 * Untrusted enrolment carries nothing of its own: the stock HAL
		 * hands the TA a zeroed common prefix and no more.
		 */
		if (step->model_kind != GFPIA_MODEL_NONE ||
		    step->payload_size != GFPIA_1060_PAYLOAD_SIZE)
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	if (step->command_class != GFPIA_CLASS_NORMAL &&
	    step->command_class != GFPIA_CLASS_TEST) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " has an invalid class %" PRIu32 "\n",
			step->command, step->command_class);
		return -EINVAL;
	}

	write_le32(expected_request + 0x08, step->expected_token);
	write_le32(expected_request + 0x0c, step->command_class);
	memcpy(expected_request + 0x10, step->request.data + 0x10,
	       sizeof(request_time));
	write_le32(expected_request + 0x18, log_level);
	write_le32(expected_request + 0x20, step->command);
	write_le32(expected_request + 0x24, (uint32_t)step->payload_size);
	write_le32(expected_payload + 0x44, step->expected_sequence);
	if (step->command == GFPIA_1014_COMMAND) {
		write_le32(expected_payload + GFPIA_ACTIVE_GROUP_GID_OFFSET, 0);
		memcpy(expected_payload + GFPIA_ACTIVE_GROUP_PATH_OFFSET,
		       GFPIA_ACTIVE_GROUP_PATH,
		       sizeof(GFPIA_ACTIVE_GROUP_PATH) - 1);
	}

	if (memcmp(step->request.data, expected_request,
		   sizeof(expected_request))) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " request contains unexpected fields\n",
			step->command);
		return -EINVAL;
	}
	if (step->command == GFPIA_1113_COMMAND)
		return validate_gfpia_model_chunk_input(step);
	if (memcmp(step->payload.data, expected_payload, step->payload.size)) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " payload is not the reviewed cold-start input\n",
			step->command);
		return -EINVAL;
	}

	return 0;
}

static int get_inherited_xiaomi_fp_fd(void)
{
	const char *value = getenv(XIAOMI_FP_FD_ENV);
	char sysfs_path[64];
	char uio_name[64];
	struct stat actual;
	char *end = NULL;
	FILE *file;
	long parsed;
	int flags;

	if (!value || !*value) {
		fprintf(stderr, "%s is not set; use xiaomi-fp-run --pass-fp-fd\n",
			XIAOMI_FP_FD_ENV);
		return -ENOENT;
	}
	errno = 0;
	parsed = strtol(value, &end, 10);
	if (errno || !end || *end || parsed < 3 || parsed > INT_MAX) {
		fprintf(stderr, "%s is not a valid inherited fd\n",
			XIAOMI_FP_FD_ENV);
		return -EINVAL;
	}
	if (fstat((int)parsed, &actual) < 0)
		return report_errno("fstat inherited fingerprint fd");
	if (!S_ISCHR(actual.st_mode)) {
		fprintf(stderr, "%s is not a character device\n",
			XIAOMI_FP_FD_ENV);
		return -ENODEV;
	}
	/*
	 * The UIO minor is whatever UIO handed out, so the descriptor is
	 * checked against the name the driver registered rather than a path.
	 */
	if (snprintf(sysfs_path, sizeof(sysfs_path), "/sys/dev/char/%u:%u/name",
		     major(actual.st_rdev), minor(actual.st_rdev)) >=
	    (int)sizeof(sysfs_path))
		return -ENAMETOOLONG;
	file = fopen(sysfs_path, "re");
	if (!file)
		return report_errno(sysfs_path);
	if (!fgets(uio_name, sizeof(uio_name), file)) {
		fclose(file);
		return -EIO;
	}
	fclose(file);
	uio_name[strcspn(uio_name, "\n")] = '\0';
	if (strcmp(uio_name, XIAOMI_FP_UIO_NAME)) {
		fprintf(stderr, "%s refers to UIO device \"%s\", not %s\n",
			XIAOMI_FP_FD_ENV, uio_name, XIAOMI_FP_UIO_NAME);
		return -ENODEV;
	}
	flags = fcntl((int)parsed, F_GETFL);
	if (flags < 0)
		return report_errno("F_GETFL inherited fingerprint fd");
	if ((flags & O_ACCMODE) != O_RDWR) {
		fprintf(stderr, "inherited fingerprint fd is not open read/write\n");
		return -EACCES;
	}

	return (int)parsed;
}

static int load_gfpia_step(int tee_fd, struct gfpia_step *step,
			   const char *request_path, const char *payload_path)
{
	int ret;

	ret = read_file(request_path, MAX_IO_BUFFER_SIZE, &step->request);
	if (ret)
		return ret;
	ret = read_file(payload_path, MAX_IO_BUFFER_SIZE, &step->payload);
	if (ret)
		return ret;
	ret = validate_gfpia_sequence_input(step);
	if (ret)
		return ret;
	ret = shared_memory_alloc(tee_fd, step->payload.size,
				  &step->shared_payload);
	if (ret)
		return ret;
	memset(step->shared_payload.data, 0, step->shared_payload.size);
	memcpy(step->shared_payload.data, step->payload.data, step->payload.size);

	return 0;
}

static int validate_gfpia_piano_model_digest(const uint8_t *logical,
					     enum gfpia_model_kind kind)
{
	static const uint8_t asp_digest[32] = {
		0x01, 0x82, 0x91, 0x94, 0xc8, 0xa1, 0xe0, 0x0b,
		0x7b, 0xf1, 0xcc, 0x04, 0x40, 0x04, 0x3b, 0xc5,
		0xee, 0x45, 0x05, 0x77, 0x91, 0xf1, 0xf1, 0xab,
		0x41, 0x0f, 0x81, 0x19, 0xbc, 0x10, 0xae, 0x4e,
	};
	static const uint8_t palm_digest[32] = {
		0x42, 0x27, 0x41, 0x92, 0x0c, 0xb2, 0xa0, 0xe5,
		0x08, 0x24, 0x1e, 0x9d, 0x1b, 0x7c, 0x82, 0x4f,
		0x73, 0x04, 0xf1, 0x5e, 0x63, 0x8b, 0x15, 0x76,
		0x42, 0x3c, 0x6f, 0xb9, 0x9f, 0x99, 0xec, 0x71,
	};
	const uint8_t *expected;
	const char *name;
	size_t model_size;
	uint8_t digest[32];

	if (kind == GFPIA_MODEL_ASP) {
		expected = asp_digest;
		model_size = GFPIA_ASP_MODEL_SIZE;
		name = "ASP CAP_S_2";
	} else if (kind == GFPIA_MODEL_PALM) {
		expected = palm_digest;
		model_size = GFPIA_PALM_MODEL_SIZE;
		name = "Piano palm";
	} else {
		return -EINVAL;
	}

	sha256_digest(logical + GFPIA_MODEL_DATA_OFFSET, model_size, digest);
	if (memcmp(digest, expected, sizeof(digest))) {
		fprintf(stderr, "%s model SHA-256 does not match stock\n", name);
		return -EINVAL;
	}
	return 0;
}

static int validate_gfpia_piano_model(const struct gfpia_step *steps,
				      size_t first_step,
				      enum gfpia_model_kind kind)
{
	uint8_t *logical;
	size_t copy_size;
	size_t i;
	int ret = -EINVAL;

	logical = malloc(GFPIA_MODEL_LOGICAL_SIZE);
	if (!logical)
		return -ENOMEM;

	for (i = 0; i < GFPIA_MODEL_CHUNK_COUNT; i++) {
		const struct gfpia_step *step = &steps[first_step + i];

		if (step->model_kind != kind || step->model_chunk != i) {
			fprintf(stderr, "Piano model chunks are out of order\n");
			goto out;
		}
		copy_size = i == GFPIA_MODEL_CHUNK_COUNT - 1 ?
			GFPIA_MODEL_REMAINDER_SIZE : GFPIA_MODEL_CHUNK_SIZE;
		memcpy(logical + i * GFPIA_MODEL_CHUNK_SIZE,
		       step->payload.data + GFPIA_COMMON_PAYLOAD_SIZE,
		       copy_size);
	}

	if (kind == GFPIA_MODEL_ASP) {
		if (!bytes_are_zero(logical, GFPIA_MODEL_DATA_OFFSET) ||
		    bytes_are_zero(logical + GFPIA_MODEL_DATA_OFFSET,
				   GFPIA_ASP_MODEL_SIZE) ||
		    !bytes_are_zero(logical + GFPIA_MODEL_DATA_OFFSET +
					GFPIA_ASP_MODEL_SIZE,
				       GFPIA_ASP_MODEL_SIZE_OFFSET -
					GFPIA_MODEL_DATA_OFFSET -
					GFPIA_ASP_MODEL_SIZE) ||
		    read_le32(logical + GFPIA_ASP_MODEL_SIZE_OFFSET) !=
			GFPIA_ASP_MODEL_SIZE ||
		    !bytes_are_zero(logical + GFPIA_ASP_MODEL_SIZE_OFFSET +
					sizeof(uint32_t),
				       GFPIA_MODEL_LOGICAL_SIZE -
					GFPIA_ASP_MODEL_SIZE_OFFSET -
					sizeof(uint32_t))) {
			fprintf(stderr, "Piano ASP logical model has invalid layout\n");
			goto out;
		}
	} else if (kind == GFPIA_MODEL_PALM) {
		if (!bytes_are_zero(logical, GFPIA_PALM_KIND_OFFSET) ||
		    read_le32(logical + GFPIA_PALM_KIND_OFFSET) != 1 ||
		    bytes_are_zero(logical + GFPIA_MODEL_DATA_OFFSET,
				   GFPIA_PALM_MODEL_SIZE) ||
		    !bytes_are_zero(logical + GFPIA_MODEL_DATA_OFFSET +
					GFPIA_PALM_MODEL_SIZE,
				       GFPIA_PALM_MODEL_SIZE_OFFSET -
					GFPIA_MODEL_DATA_OFFSET -
					GFPIA_PALM_MODEL_SIZE) ||
		    read_le32(logical + GFPIA_PALM_MODEL_SIZE_OFFSET) !=
			GFPIA_PALM_MODEL_WORDS) {
			fprintf(stderr, "Piano palm logical model has invalid layout\n");
			goto out;
		}
	} else {
		fprintf(stderr, "invalid Piano model kind\n");
		goto out;
	}

	ret = validate_gfpia_piano_model_digest(logical, kind);
out:
	free(logical);
	return ret;
}

static int prepare_gfpia_output(const char *path, int *fd)
{
	*fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (*fd < 0)
		return report_errno(path);
	return 0;
}

static int prepare_gfpia_step_outputs(struct gfpia_step *step)
{
	int ret;

	ret = prepare_gfpia_output(step->request_output_path,
				   &step->request_output_fd);
	if (ret)
		return ret;
	ret = prepare_gfpia_output(step->response_path, &step->response_fd);
	if (ret)
		return ret;
	return prepare_gfpia_output(step->payload_output_path,
				    &step->payload_output_fd);
}

static void discard_gfpia_step_outputs(struct gfpia_step *step)
{
	if (step->request_output_fd >= 0) {
		close(step->request_output_fd);
		step->request_output_fd = -1;
		unlink(step->request_output_path);
	}
	if (step->response_fd >= 0) {
		close(step->response_fd);
		step->response_fd = -1;
		unlink(step->response_path);
	}
	if (step->payload_output_fd >= 0) {
		close(step->payload_output_fd);
		step->payload_output_fd = -1;
		unlink(step->payload_output_path);
	}
}

static int write_gfpia_step_outputs(struct gfpia_step *step)
{
	struct blob payload_output = {
		.data = step->shared_payload.data,
		.size = step->payload.size,
	};
	int ret;

	ret = write_open_file(step->request_output_fd, step->request_output_path,
			      &step->request_output);
	if (ret)
		return ret;
	ret = write_open_file(step->response_fd, step->response_path,
			      &step->response);
	if (ret)
		return ret;
	ret = write_open_file(step->payload_output_fd, step->payload_output_path,
			      &payload_output);
	if (ret)
		return ret;
	step->outputs_written = true;

	fprintf(stdout,
		"%s: wrote patched request, response, and payload outputs\n",
		step->label);
	return 0;
}

static int validate_gfpia_step_result(const struct gfpia_step *step,
				      uint8_t expected_fw_info)
{
	uint32_t sequence;
	uint32_t auxiliary;
	uint32_t status;
	uint16_t nav_polarity;
	uint16_t orientation;
	uint64_t address;

	if (step->request_output.size != GFPIA_REQUEST_SIZE) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " returned a short patched request\n",
			step->command);
		return -EPROTO;
	}
	if (step->response.size != GFPIA_RESPONSE_SIZE) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " returned a response of 0x%zx bytes\n",
			step->command, step->response.size);
		return -EPROTO;
	}
	if (memcmp(step->request_output.data + sizeof(uint64_t),
		   step->request.data + sizeof(uint64_t),
		   GFPIA_REQUEST_SIZE - sizeof(uint64_t))) {
		fprintf(stderr,
			"gfpia command %" PRIu32
			" changed patched-request fields outside the payload address\n",
			step->command);
		return -EPROTO;
	}

	status = read_le32(step->response.data);
	auxiliary = read_le32(step->response.data + sizeof(uint32_t));
	fprintf(stdout,
		"%s: status 0x%08" PRIx32
		", auxiliary 0x%08" PRIx32 "\n",
		step->label, status, auxiliary);
	if (auxiliary) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " returned auxiliary error 0x%08" PRIx32 "\n",
			step->command, auxiliary);
		return -EREMOTEIO;
	}
	if (status) {
		fprintf(stderr,
			"gfpia command %" PRIu32 " returned TA status 0x%08" PRIx32 "\n",
			step->command, status);
		return -EREMOTEIO;
	}

	address = read_le64(step->request_output.data);
	if (!address || address > UINT32_MAX ||
	    step->payload.size - 1 > UINT32_MAX - (uint32_t)address) {
		fprintf(stderr,
			"gfpia command %" PRIu32
			" payload range at 0x%" PRIx64 " is not below 4 GiB\n",
			step->command, address);
		return -ERANGE;
	}
	fprintf(stdout, "command %" PRIu32 ": payload PA 0x%" PRIx64 "\n",
		step->command, address);

	sequence = read_le32(step->shared_payload.data + 0x44);
	if (sequence != step->expected_sequence) {
		fprintf(stderr,
			"%s changed sequence from 0x%08" PRIx32
			" to 0x%08" PRIx32 "\n",
			step->label, step->expected_sequence, sequence);
		return -EPROTO;
	}

	if (step->command == GFPIA_1000_COMMAND &&
	    step->shared_payload.data[0x70] != 0x31) {
		fprintf(stderr,
			"gfpia command 1000 returned unexpected config byte 0x%02x\n",
			step->shared_payload.data[0x70]);
		return -EPROTO;
	}
	if (step->command == GFPIA_1001_COMMAND &&
	    step->shared_payload.data[0x6c] != expected_fw_info) {
		fprintf(stderr,
			"gfpia command 1001 did not preserve fw_info 0x%02x\n",
			expected_fw_info);
		return -EPROTO;
	}
	if (step->command == GFPIA_1005_COMMAND) {
		orientation = read_le16(step->shared_payload.data + 0x6c);
		if (orientation != 0 && orientation != 90 &&
		    orientation != 180 && orientation != 270) {
			fprintf(stderr,
				"gfpia command 1005 returned invalid orientation %u\n",
				orientation);
			return -EPROTO;
		}
		nav_polarity = read_le16(step->shared_payload.data + 0x6e);
		fprintf(stdout,
			"command 1005: orientation %u, navigation polarity %u\n",
			orientation, nav_polarity);
	}

	return 0;
}

static int validate_gfpia_hlos_gate(const struct gfpia_step *step,
				    uint8_t expected_fw_info)
{
	uint32_t otp_size;

	if (step->command != GFPIA_1001_COMMAND ||
	    step->payload.size != GFPIA_1001_PAYLOAD_SIZE) {
		fprintf(stderr,
			"HLOS init requires an exact 0x%x-byte command-1001 payload\n",
			GFPIA_1001_PAYLOAD_SIZE);
		return -EPROTO;
	}
	if (step->shared_payload.data[0x6c] != expected_fw_info) {
		fprintf(stderr,
			"HLOS init rejected command 1001: fw_info changed from 0x%02x to 0x%02x\n",
			expected_fw_info, step->shared_payload.data[0x6c]);
		return -EPROTO;
	}
	if (step->shared_payload.data[0x165] != GFPIA_1001_MATCH_VERSION) {
		fprintf(stderr,
			"HLOS init rejected command 1001 match version 0x%02x\n",
			step->shared_payload.data[0x165]);
		return -EPROTO;
	}

	otp_size = read_le32(step->shared_payload.data + 0x158);
	if (otp_size > GFPIA_1001_MAX_OTP_SIZE) {
		fprintf(stderr,
			"HLOS init rejected command 1001 OTP size 0x%08" PRIx32 "\n",
			otp_size);
		return -EPROTO;
	}

	return 0;
}

static void release_gfpia_step(struct gfpia_step *step)
{
	free(step->request.data);
	free(step->request_output.data);
	free(step->response.data);
	free(step->payload.data);
	shared_memory_release(&step->shared_payload);
	if (step->request_output_fd >= 0)
		close(step->request_output_fd);
	if (step->response_fd >= 0)
		close(step->response_fd);
	if (step->payload_output_fd >= 0)
		close(step->payload_output_fd);
	if (!step->outputs_written) {
		if (step->request_output_fd >= 0)
			unlink(step->request_output_path);
		if (step->response_fd >= 0)
			unlink(step->response_path);
		if (step->payload_output_fd >= 0)
			unlink(step->payload_output_path);
	}
}

static void initialize_gfpia_step(struct gfpia_step *step, const char *label,
				  uint32_t command, uint32_t command_class,
				  size_t payload_size,
				  uint32_t token, uint32_t sequence,
				  enum gfpia_model_kind model_kind,
				  uint8_t model_chunk,
				  const char *response_path,
				  const char *payload_output_path,
				  const char *request_output_path)
{
	*step = (struct gfpia_step) {
		.shared_payload = { .id = -1, .fd = -1 },
		.response_path = response_path,
		.payload_output_path = payload_output_path,
		.request_output_path = request_output_path,
		.response_fd = -1,
		.payload_output_fd = -1,
		.request_output_fd = -1,
		.label = label,
		.command = command,
		.command_class = command_class,
		.expected_token = token,
		.expected_sequence = sequence,
		.payload_size = payload_size,
		.model_kind = model_kind,
		.model_chunk = model_chunk,
	};
}

static int invoke_gfpia_step(int tee_fd, struct qtee_object controller,
			     struct gfpia_step *step, uint8_t expected_fw_info)
{
	int ret;

	ret = send_request(tee_fd, controller, &step->request,
			   &step->shared_payload, GFPIA_RESPONSE_SIZE,
			   &step->request_output, &step->response);
	if (ret)
		return ret;

	ret = write_gfpia_step_outputs(step);
	if (ret)
		return ret;

	return validate_gfpia_step_result(step, expected_fw_info);
}

static int validate_keymaster_hmac_response_only_common(
				const struct blob *response, bool diagnostics)
{
	uint32_t message_offset;
	uint32_t message_length;
	uint32_t status;

	if (!response || !response->data || response->size < sizeof(status)) {
		if (diagnostics)
			fprintf(stderr,
				"keymaster64 returned a truncated HMAC status\n");
		return -EPROTO;
	}

	status = read_le32(response->data);
	if (status) {
		if (diagnostics)
			fprintf(stderr,
				"keymaster64 HMAC request returned status 0x%08"
				PRIx32 " (%" PRId32 ")\n", status,
				(int32_t)status);
		return -EREMOTEIO;
	}
	if (response->size != KEYMASTER_HMAC_RESPONSE_SIZE) {
		if (diagnostics)
			fprintf(stderr,
				"keymaster64 returned 0x%zx bytes, expected 0x%x\n",
				response->size, KEYMASTER_HMAC_RESPONSE_SIZE);
		return -EPROTO;
	}

	message_offset = read_le32(response->data + KEYMASTER_HMAC_OFFSET_OFFSET);
	message_length = read_le32(response->data + KEYMASTER_HMAC_LENGTH_OFFSET);
	if (message_offset < KEYMASTER_HMAC_HEADER_SIZE || !message_length ||
	    message_offset > response->size ||
	    message_length > response->size - message_offset) {
		if (diagnostics)
			fprintf(stderr,
				"keymaster64 returned invalid encapsulated-message bounds\n");
		return -EPROTO;
	}

	return 0;
}

static int validate_keymaster_hmac_response_only(const struct blob *response)
{
	return validate_keymaster_hmac_response_only_common(response, true);
}

static int validate_keymaster_hmac_response(const struct blob *request,
					    const struct blob *request_output,
					    const struct blob *response)
{
	if (!request || !request->data || !request_output ||
	    !request_output->data ||
	    request_output->size != KEYMASTER_HMAC_REQUEST_SIZE ||
	    request->size != KEYMASTER_HMAC_REQUEST_SIZE ||
	    memcmp(request->data, request_output->data, request->size)) {
		fprintf(stderr, "keymaster64 changed or truncated the HMAC request\n");
		return -EPROTO;
	}

	return validate_keymaster_hmac_response_only(response);
}

static int validate_keymaster_service_hmac_response_common(
				const struct blob *response, bool diagnostics)
{
	uint32_t status;
	int ret;

	if (!response || !response->data || response->size < sizeof(status)) {
		if (diagnostics)
			fprintf(stderr,
				"Keymaster service returned a truncated private-HMAC status\n");
		return -EPROTO;
	}

	status = read_le32(response->data);
	if (status) {
		if (diagnostics)
			fprintf(stderr,
				"Keymaster service private-HMAC request returned status "
				"0x%08" PRIx32 " (%" PRId32 ")\n",
				status, (int32_t)status);
		return -EREMOTEIO;
	}
	if (response->size < KEYMASTER_HMAC_RESPONSE_SIZE) {
		if (diagnostics)
			fprintf(stderr,
				"Keymaster service returned 0x%zx private-HMAC bytes, "
				"expected at least 0x%x\n",
				response->size, KEYMASTER_HMAC_RESPONSE_SIZE);
		return -EPROTO;
	}

	/* The IKMHal output may report capacity; only this fixed view is logical. */
	const struct blob logical_response = {
		.data = response->data,
		.size = KEYMASTER_HMAC_RESPONSE_SIZE,
	};

	ret = validate_keymaster_hmac_response_only_common(&logical_response,
							  diagnostics);
	return ret;
}

static int validate_keymaster_service_hmac_response(
				const struct blob *response)
{
	return validate_keymaster_service_hmac_response_common(response, true);
}

static int validate_gfpia_hmac_result(const struct blob *request,
				      const struct blob *request_output,
				      const struct blob *response)
{
	uint32_t auxiliary;
	uint32_t status;
	uint64_t address;

	if (request_output->size != GFPIA_REQUEST_SIZE ||
	    response->size != GFPIA_RESPONSE_SIZE) {
		fprintf(stderr, "gfpia command 109 returned invalid output sizes\n");
		return -EPROTO;
	}
	if (memcmp(request_output->data + sizeof(uint64_t),
		   request->data + sizeof(uint64_t),
		   GFPIA_REQUEST_SIZE - sizeof(uint64_t))) {
		fprintf(stderr,
			"gfpia command 109 changed request fields outside the payload address\n");
		return -EPROTO;
	}

	status = read_le32(response->data);
	auxiliary = read_le32(response->data + sizeof(uint32_t));
	fprintf(stdout,
		"command 109 HMAC: status 0x%08" PRIx32
		", auxiliary 0x%08" PRIx32 "\n",
		status, auxiliary);
	if (auxiliary || status)
		return -EREMOTEIO;

	address = read_le64(request_output->data);
	if (!address || address > UINT32_MAX ||
	    GFPIA_109_PAYLOAD_SIZE - 1U >
		UINT32_MAX - (uint32_t)address) {
		fprintf(stderr,
			"gfpia command 109 payload range is not below 4 GiB\n");
		return -ERANGE;
	}

	return 0;
}

static void build_keymaster_hmac_request(uint8_t *request)
{
	memset(request, 0, KEYMASTER_HMAC_REQUEST_SIZE);
	write_le32(request, KEYMASTER_HMAC_COMMAND);
	write_le32(request + sizeof(uint32_t), KEYMASTER_HMAC_SELECTOR);
}

static void build_gfpia_hmac_request(uint8_t *request, uint64_t request_time,
				     uint32_t log_level)
{
	memset(request, 0, GFPIA_REQUEST_SIZE);
	write_le32(request + 0x08, GFPIA_HMAC_TOKEN);
	write_le32(request + 0x0c, GFPIA_HMAC_CLASS);
	write_le64(request + 0x10, request_time);
	write_le32(request + 0x18, log_level);
	write_le32(request + 0x20, GFPIA_109_COMMAND);
	write_le32(request + 0x24, GFPIA_109_PAYLOAD_SIZE);
}

static int request_keymaster_hmac(int tee_fd,
				  struct qtee_object *keymaster_controller,
				  struct blob *keymaster_response)
{
	uint8_t keymaster_request_data[KEYMASTER_HMAC_REQUEST_SIZE] = { 0 };
	struct blob keymaster_request = {
		.data = keymaster_request_data,
		.size = sizeof(keymaster_request_data),
	};
	struct blob keymaster_request_output = { 0 };
	int cleanup_ret;
	int ret;

	build_keymaster_hmac_request(keymaster_request_data);
	ret = send_request(tee_fd, *keymaster_controller, &keymaster_request,
			   NULL, KEYMASTER_HMAC_RESPONSE_SIZE,
			   &keymaster_request_output, keymaster_response);
	cleanup_ret = object_release(tee_fd, keymaster_controller);
	if (cleanup_ret) {
		fprintf(stderr, "failed to release keymaster64 controller\n");
		if (!ret)
			ret = cleanup_ret;
	}
	if (!ret)
		ret = validate_keymaster_hmac_response(&keymaster_request,
						       &keymaster_request_output,
						       keymaster_response);

	secure_free_blob(&keymaster_request_output);
	secure_clear(keymaster_request_data, sizeof(keymaster_request_data));
	if (ret)
		secure_free_blob(keymaster_response);
	return ret;
}

static int request_keymaster_service_private_hmac(
				int tee_fd, struct qtee_object keymaster)
{
	uint8_t request_data[KEYMASTER_HMAC_REQUEST_SIZE] = { 0 };
	struct blob response = { 0 };
	int ret;

	build_keymaster_hmac_request(request_data);
	ret = keymaster_send_service_command(tee_fd, keymaster, request_data,
					     sizeof(request_data), &response);
	if (!ret)
		ret = validate_keymaster_service_hmac_response(&response);
	if (!ret)
		fprintf(stdout,
			"Keymaster service returned a valid fixed private-HMAC envelope\n");

	secure_free_blob(&response);
	secure_clear(request_data, sizeof(request_data));
	return ret;
}

static int probe_keymaster_service_shared_hmac_private(
				int tee_fd, struct qtee_object client_env)
{
	struct keymaster_service service;
	int cleanup_ret;
	int ret;

	ret = keymaster_service_open(tee_fd, client_env, &service);
	if (ret)
		goto out;
	ret = keymaster_service_get_version(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_version(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_get_date_support(tee_fd, service.hal, true);
	if (ret)
		goto out;
	ret = keymaster_service_set_keymint_version(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_configure(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_agree_shared_hmac(tee_fd, service.hal);
	if (ret)
		goto out;
	/* This helper contains exactly one private command send and no retry. */
	ret = request_keymaster_service_private_hmac(tee_fd, service.hal);

out:
	cleanup_ret = keymaster_service_release(tee_fd, &service);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	if (!ret)
		fprintf(stdout,
			"Keymaster shared-HMAC and private-HMAC probe completed\n");
	return ret;
}

static int probe_keymaster_service_shared_hmac_direct_private(
				int tee_fd, struct qtee_object client_env,
				const char *keymaster_source)
{
	struct keymaster_service service = {
		.app_client = { .id = TEE_OBJREF_NULL },
		.opener = { .id = TEE_OBJREF_NULL },
		.hal = { .id = TEE_OBJREF_NULL },
	};
	struct qtee_object loader = { .id = TEE_OBJREF_NULL };
	struct qtee_object controller = { .id = TEE_OBJREF_NULL };
	struct blob source_image = { 0 };
	struct blob response = { 0 };
	int cleanup_ret;
	int ret;

	/* Reject a missing or malformed explicit source before touching Keymaster. */
	ret = load_image_source(keymaster_source, KEYMASTER_APP_NAME,
				&source_image);
	if (!ret)
		fprintf(stdout,
			"validated explicit keymaster64 image source (%zu bytes)\n",
			source_image.size);
	secure_free_blob(&source_image);
	if (ret)
		return ret;

	ret = keymaster_service_open(tee_fd, client_env, &service);
	if (ret)
		goto out;
	ret = keymaster_service_get_version(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_set_version(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_get_date_support(tee_fd, service.hal, true);
	if (ret)
		goto out;
	ret = keymaster_service_set_keymint_version(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_configure(tee_fd, service.hal);
	if (ret)
		goto out;
	ret = keymaster_service_agree_shared_hmac(tee_fd, service.hal);
	if (ret)
		goto out;

	/* The direct fallback is unreachable until every public lifecycle gate. */
	ret = client_env_open(tee_fd, client_env,
			      QSEECOM_COMPAT_APP_LOADER_UID, &loader);
	if (ret)
		goto out;
	ret = start_app(tee_fd, loader, KEYMASTER_APP_NAME, keymaster_source,
			&controller);
	if (ret)
		goto out;
	fprintf(stdout, "direct keymaster64 controller object: %" PRIu64 "\n",
		controller.id);

	/* This is the only private-command send in this isolated fallback. */
	ret = request_keymaster_hmac(tee_fd, &controller, &response);
	if (!ret)
		fprintf(stdout,
			"direct keymaster64 returned a valid fixed private-HMAC envelope\n");
	secure_free_blob(&response);

out:
	secure_free_blob(&response);
	cleanup_ret = object_release(tee_fd, &controller);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	cleanup_ret = object_release(tee_fd, &loader);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	cleanup_ret = keymaster_service_release(tee_fd, &service);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	if (!ret)
		fprintf(stdout,
			"Keymaster shared-HMAC and isolated direct private-HMAC probe completed\n");
	return ret;
}

static int send_gfpia_hmac_key(int tee_fd,
			       struct qtee_object gfpia_controller,
			       struct qtee_object *keymaster_controller,
			       uint64_t request_time, uint32_t log_level)
{
	uint8_t gfpia_request_data[GFPIA_REQUEST_SIZE] = { 0 };
	struct blob gfpia_request = {
		.data = gfpia_request_data,
		.size = sizeof(gfpia_request_data),
	};
	struct blob keymaster_response = { 0 };
	struct blob gfpia_request_output = { 0 };
	struct blob gfpia_response = { 0 };
	struct qtee_shared_memory shared_hmac = {
		.id = -1,
		.fd = -1,
	};
	int cleanup_ret;
	int ret;

	ret = request_keymaster_hmac(tee_fd, keymaster_controller,
				     &keymaster_response);
	if (ret)
		goto out;

	ret = shared_memory_alloc(tee_fd, GFPIA_109_PAYLOAD_SIZE, &shared_hmac);
	if (ret)
		goto out;
	memset(shared_hmac.data, 0, shared_hmac.size);
	memcpy(shared_hmac.data, keymaster_response.data,
	       KEYMASTER_HMAC_RESPONSE_SIZE);
	secure_free_blob(&keymaster_response);

	build_gfpia_hmac_request(gfpia_request_data, request_time, log_level);

	ret = send_request(tee_fd, gfpia_controller, &gfpia_request,
			   &shared_hmac, GFPIA_RESPONSE_SIZE,
			   &gfpia_request_output, &gfpia_response);
	if (!ret)
		ret = validate_gfpia_hmac_result(&gfpia_request,
						  &gfpia_request_output,
						  &gfpia_response);
	if (!ret)
		fprintf(stdout, "keymaster64 HMAC installed in gfpia\n");

out:
	if (keymaster_controller->id != TEE_OBJREF_NULL) {
		cleanup_ret = object_release(tee_fd, keymaster_controller);
		if (!ret && cleanup_ret)
			ret = cleanup_ret;
	}
	secure_free_blob(&keymaster_response);
	secure_free_blob(&gfpia_request_output);
	secure_free_blob(&gfpia_response);
	secure_shared_memory_release(&shared_hmac);
	secure_clear(gfpia_request_data, sizeof(gfpia_request_data));
	return ret;
}

#define SHARED_HMAC_SELFTEST_REQUIRE(condition, description)              \
	do {                                                               \
		if (!(condition)) {                                          \
			fprintf(stderr,                                        \
				"shared-HMAC self-test failed: %s\n",        \
				description);                                   \
			ret = -EINVAL;                                       \
			goto out;                                             \
		}                                                          \
	} while (0)

static int run_shared_hmac_self_test(void)
{
	static const uint8_t expected_get_request[] = {
		0x0e, 0x22, 0x00, 0x00,
	};
	static const uint8_t expected_compute_header[] = {
		0x0f, 0x22, 0x00, 0x00, 0xa1, 0x18, 0x2b, 0x58, 0x40,
	};
	static const size_t get_framing_offsets[] = {
		0U, 1U, 2U, 3U, 4U,
		KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET,
		KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET + 1U,
		KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET + 2U,
		KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET + 3U,
	};
	uint8_t get_request[KEYMASTER_GET_SHARED_HMAC_REQUEST_SIZE] = { 0 };
	uint8_t compute_request[KEYMASTER_COMPUTE_SHARED_HMAC_REQUEST_SIZE] = { 0 };
	uint8_t get_response_data[128] = { 0 };
	uint8_t compute_response_data[128] = { 0 };
	uint8_t date_response_data[sizeof(uint32_t)] = { 0 };
	struct keymaster_hmac_parameters expected_parameters = { 0 };
	struct keymaster_hmac_parameters parameters = { 0 };
	struct blob get_response = {
		.data = get_response_data,
		.size = sizeof(get_response_data),
	};
	struct blob compute_response = {
		.data = compute_response_data,
		.size = sizeof(compute_response_data),
	};
	struct blob date_response = {
		.data = date_response_data,
		.size = sizeof(date_response_data),
	};
	uint8_t *get_cbor = get_response_data + KEYMASTER_RESPONSE_HEADER_SIZE;
	uint8_t *compute_cbor =
		compute_response_data + KEYMASTER_RESPONSE_HEADER_SIZE;
	size_t i;
	int ret = -EINVAL;

	for (i = 0; i < KEYMASTER_HMAC_VALUE_SIZE; i++) {
		expected_parameters.seed[i] = (uint8_t)i;
		expected_parameters.nonce[i] = (uint8_t)(0x80U + i);
	}

	build_keymaster_get_shared_hmac_request(get_request);
	SHARED_HMAC_SELFTEST_REQUIRE(
		!memcmp(get_request, expected_get_request, sizeof(get_request)),
		"build exact four-byte get request");

	build_keymaster_compute_shared_hmac_request(compute_request,
						    &expected_parameters);
	SHARED_HMAC_SELFTEST_REQUIRE(
		!memcmp(compute_request, expected_compute_header,
			sizeof(expected_compute_header)) &&
		!memcmp(compute_request + KEYMASTER_COMPUTE_SHARED_HMAC_RECORD_OFFSET,
			expected_parameters.seed,
			sizeof(expected_parameters.seed)) &&
		!memcmp(compute_request + KEYMASTER_COMPUTE_SHARED_HMAC_NONCE_OFFSET,
			expected_parameters.nonce,
			sizeof(expected_parameters.nonce)),
		"build exact 73-byte single-record compute request");

	write_le32(date_response_data, 0);
	SHARED_HMAC_SELFTEST_REQUIRE(
		!validate_keymaster_date_support_response(&date_response, true),
		"accept full-date support for the shared-HMAC chain");
	write_le32(date_response_data, (uint32_t)-40);
	SHARED_HMAC_SELFTEST_REQUIRE(
		!validate_keymaster_date_support_response(&date_response, false),
		"retain the standalone month-only date diagnostic");
	SHARED_HMAC_SELFTEST_REQUIRE(
		validate_keymaster_date_support_response(&date_response, true) ==
			-EOPNOTSUPP,
		"reject month-only patchlevels in the shared-HMAC chain");
	write_le32(date_response_data, 1U);
	SHARED_HMAC_SELFTEST_REQUIRE(
		validate_keymaster_date_support_response(&date_response, true) ==
			-EREMOTEIO,
		"reject an unexpected date-support status");
	date_response.size--;
	SHARED_HMAC_SELFTEST_REQUIRE(
		validate_keymaster_date_support_response(&date_response, true) ==
			-EPROTO,
		"reject a truncated date-support status");
	date_response.size++;

	memset(get_response_data, 0xa5, sizeof(get_response_data));
	write_le32(get_response_data, 0);
	write_le32(get_response_data + sizeof(uint32_t),
		   KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE);
	get_cbor[0] = 0xa2;
	get_cbor[1] = 0x18;
	get_cbor[2] = 0x29;
	get_cbor[3] = 0x58;
	get_cbor[4] = 0x20;
	memcpy(get_cbor + KEYMASTER_GET_SHARED_HMAC_SEED_OFFSET,
	       expected_parameters.seed,
	       sizeof(expected_parameters.seed));
	get_cbor[KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET] = 0x18;
	get_cbor[KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET + 1U] = 0x2a;
	get_cbor[KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET + 2U] = 0x58;
	get_cbor[KEYMASTER_GET_SHARED_HMAC_SECOND_FIELD_OFFSET + 3U] = 0x20;
	memcpy(get_cbor + KEYMASTER_GET_SHARED_HMAC_NONCE_OFFSET,
	       expected_parameters.nonce,
	       sizeof(expected_parameters.nonce));
	SHARED_HMAC_SELFTEST_REQUIRE(
		!decode_keymaster_get_shared_hmac_response(&get_response,
							   &parameters) &&
		!memcmp(&parameters, &expected_parameters, sizeof(parameters)),
		"decode canonical get response from a capacity-sized blob");
	for (i = KEYMASTER_RESPONSE_HEADER_SIZE +
		 KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE;
	     i < sizeof(get_response_data); i++)
		SHARED_HMAC_SELFTEST_REQUIRE(get_response_data[i] == 0xa5,
			"leave get-response transport tail untouched");
	memset(get_cbor + KEYMASTER_GET_SHARED_HMAC_SEED_OFFSET, 0,
	       KEYMASTER_HMAC_VALUE_SIZE);
	memset(get_cbor + KEYMASTER_GET_SHARED_HMAC_NONCE_OFFSET, 0,
	       KEYMASTER_HMAC_VALUE_SIZE);
	SHARED_HMAC_SELFTEST_REQUIRE(
		!decode_keymaster_get_shared_hmac_response(&get_response,
							   &parameters) &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"accept structurally valid all-zero seed and nonce values");

	memset(compute_response_data, 0xa5, sizeof(compute_response_data));
	write_le32(compute_response_data, 0);
	write_le32(compute_response_data + sizeof(uint32_t),
		   KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE);
	compute_cbor[0] = 0xa1;
	compute_cbor[1] = 0x18;
	compute_cbor[2] = 0x2c;
	compute_cbor[3] = 0x58;
	compute_cbor[4] = 0x20;
	memset(compute_cbor + KEYMASTER_COMPUTE_SHARED_HMAC_CHECK_OFFSET, 0,
	       KEYMASTER_HMAC_VALUE_SIZE);
	SHARED_HMAC_SELFTEST_REQUIRE(
		!validate_keymaster_compute_shared_hmac_response(&compute_response),
		"accept canonical compute response with an opaque check");
	for (i = KEYMASTER_RESPONSE_HEADER_SIZE +
		 KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE;
	     i < sizeof(compute_response_data); i++)
		SHARED_HMAC_SELFTEST_REQUIRE(compute_response_data[i] == 0xa5,
			"leave compute-response transport tail untouched");
	for (i = 0; i < KEYMASTER_HMAC_VALUE_SIZE; i++) {
		compute_cbor[KEYMASTER_COMPUTE_SHARED_HMAC_CHECK_OFFSET + i] ^= 1U;
		SHARED_HMAC_SELFTEST_REQUIRE(
			!validate_keymaster_compute_shared_hmac_response(
				&compute_response),
			"treat every sharing-check byte as opaque");
		compute_cbor[KEYMASTER_COMPUTE_SHARED_HMAC_CHECK_OFFSET + i] ^= 1U;
	}

	get_response.size = 3U;
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EPROTO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"reject a truncated get status and clear decoded parameters");
	get_response.size = sizeof(uint32_t);
	write_le32(get_response_data, (uint32_t)-38);
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EREMOTEIO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"handle a four-byte nonzero status without parsing CBOR");
	get_response.size = sizeof(get_response_data);
	write_le32(get_response_data, (uint32_t)-38);
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EREMOTEIO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"ignore fake CBOR following a nonzero status");
	write_le32(get_response_data, 0);
	get_response.size = KEYMASTER_RESPONSE_HEADER_SIZE - 1U;
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EPROTO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"reject a truncated successful envelope");
	get_response.size = sizeof(get_response_data);
	write_le32(get_response_data + sizeof(uint32_t),
		   (uint32_t)(sizeof(get_response_data) -
			      KEYMASTER_RESPONSE_HEADER_SIZE + 1U));
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EPROTO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"reject a declared payload beyond the transport blob");
	write_le32(get_response_data + sizeof(uint32_t), UINT32_MAX);
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EPROTO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"reject UINT32_MAX payload length without overflow");

	write_le32(get_response_data + sizeof(uint32_t),
		   KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE - 1U);
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EPROTO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"reject a short get CBOR schema");
	write_le32(get_response_data + sizeof(uint32_t),
		   KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE + 1U);
	memset(&parameters, 0xa5, sizeof(parameters));
	SHARED_HMAC_SELFTEST_REQUIRE(
		decode_keymaster_get_shared_hmac_response(&get_response,
							  &parameters) == -EPROTO &&
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)),
		"reject trailing bytes inside declared get CBOR");
	write_le32(get_response_data + sizeof(uint32_t),
		   KEYMASTER_GET_SHARED_HMAC_CBOR_SIZE);
	for (i = 0; i < ARRAY_SIZE(get_framing_offsets); i++) {
		get_cbor[get_framing_offsets[i]] ^= 1U;
		memset(&parameters, 0xa5, sizeof(parameters));
		SHARED_HMAC_SELFTEST_REQUIRE(
			decode_keymaster_get_shared_hmac_response(&get_response,
								  &parameters) == -EPROTO &&
			bytes_are_zero((const uint8_t *)&parameters,
				       sizeof(parameters)),
			"reject mutated get framing and clear output");
		get_cbor[get_framing_offsets[i]] ^= 1U;
	}

	write_le32(compute_response_data + sizeof(uint32_t),
		   KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE - 1U);
	SHARED_HMAC_SELFTEST_REQUIRE(
		validate_keymaster_compute_shared_hmac_response(&compute_response) ==
			-EPROTO,
		"reject a short compute CBOR schema");
	write_le32(compute_response_data + sizeof(uint32_t),
		   KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE + 1U);
	SHARED_HMAC_SELFTEST_REQUIRE(
		validate_keymaster_compute_shared_hmac_response(&compute_response) ==
			-EPROTO,
		"reject trailing bytes inside declared compute CBOR");
	write_le32(compute_response_data + sizeof(uint32_t),
		   KEYMASTER_COMPUTE_SHARED_HMAC_RESPONSE_CBOR_SIZE);
	for (i = 0; i < 5U; i++) {
		compute_cbor[i] ^= 1U;
		SHARED_HMAC_SELFTEST_REQUIRE(
			validate_keymaster_compute_shared_hmac_response(
				&compute_response) == -EPROTO,
			"reject mutated compute framing");
		compute_cbor[i] ^= 1U;
	}

	memset(&parameters, 0xa5, sizeof(parameters));
	memset(compute_request, 0xa5, sizeof(compute_request));
	secure_clear(&parameters, sizeof(parameters));
	secure_clear(compute_request, sizeof(compute_request));
	SHARED_HMAC_SELFTEST_REQUIRE(
		bytes_are_zero((const uint8_t *)&parameters, sizeof(parameters)) &&
		bytes_are_zero(compute_request, sizeof(compute_request)),
		"clear shared-HMAC parameter and request owners");

	ret = 0;
out:
	secure_clear(get_request, sizeof(get_request));
	secure_clear(compute_request, sizeof(compute_request));
	secure_clear(get_response_data, sizeof(get_response_data));
	secure_clear(compute_response_data, sizeof(compute_response_data));
	secure_clear(date_response_data, sizeof(date_response_data));
	secure_clear(&expected_parameters, sizeof(expected_parameters));
	secure_clear(&parameters, sizeof(parameters));
	return ret;
}

#undef SHARED_HMAC_SELFTEST_REQUIRE

#define HMAC_SELFTEST_REQUIRE(condition, description)                    \
	do {                                                              \
		if (!(condition)) {                                         \
			fprintf(stderr, "HMAC self-test failed: %s\n",       \
				description);                                  \
			return -EINVAL;                                      \
		}                                                         \
	} while (0)

static int run_hmac_self_test(void)
{
	static const uint8_t expected_keymint_version_request[] = {
		0x21, 0x31, 0x00, 0x00, 0xa1, 0x0b, 0x19, 0x01, 0x2c,
	};
	static const uint8_t expected_date_support_request[] = {
		0x15, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	static const uint8_t expected_configure_request[] = {
		0x16, 0x21, 0x00, 0x00,
		0xa4, 0x16, 0x03,
		0x1a, 0x30, 0x00, 0x02, 0xc1,
		0x1a, 0x00, 0x02, 0x71, 0x00,
		0x1a, 0x30, 0x00, 0x02, 0xc2,
		0x1a, 0x01, 0x35, 0x27, 0x5d,
		0x1a, 0x30, 0x00, 0x02, 0xce,
		0x1a, 0x01, 0x35, 0x25, 0x69,
	};
	static const uint8_t expected_keymaster_hmac_request[] = {
		0x05, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	};
	static const uint64_t request_time = UINT64_C(0x0123456789abcdef);
	static const uint32_t log_level = UINT32_C(0x76543210);
	uint8_t keymint_version_request[KEYMASTER_KEYMINT_SET_VERSION_REQUEST_SIZE];
	uint8_t date_support_request[KEYMASTER_GET_DATE_SUPPORT_REQUEST_SIZE];
	uint8_t configure_request[KEYMASTER_CONFIGURE_REQUEST_SIZE];
	uint8_t keymaster_request_data[KEYMASTER_HMAC_REQUEST_SIZE];
	uint8_t keymaster_request_output_data[KEYMASTER_HMAC_REQUEST_SIZE];
	uint8_t keymaster_response_data[KEYMASTER_HMAC_RESPONSE_SIZE];
	uint8_t service_hmac_response_data[
		KEYMASTER_SERVICE_HMAC_RESPONSE_CAPACITY];
	uint8_t gfpia_request_data[GFPIA_REQUEST_SIZE];
	uint8_t gfpia_request_output_data[GFPIA_REQUEST_SIZE];
	uint8_t gfpia_response_data[GFPIA_RESPONSE_SIZE] = { 0 };
	uint8_t expected_gfpia_request[GFPIA_REQUEST_SIZE] = { 0 };
	uint8_t cleared_data[KEYMASTER_HMAC_RESPONSE_SIZE];
	struct blob keymaster_request = {
		.data = keymaster_request_data,
		.size = sizeof(keymaster_request_data),
	};
	struct blob keymaster_request_output = {
		.data = keymaster_request_output_data,
		.size = sizeof(keymaster_request_output_data),
	};
	struct blob keymaster_response = {
		.data = keymaster_response_data,
		.size = sizeof(keymaster_response_data),
	};
	struct blob service_hmac_response = {
		.data = service_hmac_response_data,
		.size = sizeof(service_hmac_response_data),
	};
	struct blob gfpia_request = {
		.data = gfpia_request_data,
		.size = sizeof(gfpia_request_data),
	};
	struct blob gfpia_request_output = {
		.data = gfpia_request_output_data,
		.size = sizeof(gfpia_request_output_data),
	};
	struct blob gfpia_response = {
		.data = gfpia_response_data,
		.size = sizeof(gfpia_response_data),
	};
	size_t i;
	int ret;

	ret = run_shared_hmac_self_test();
	if (ret)
		return ret;

	build_keymaster_keymint_version_request(keymint_version_request);
	HMAC_SELFTEST_REQUIRE(!memcmp(keymint_version_request,
					       expected_keymint_version_request,
					       sizeof(keymint_version_request)),
				      "build exact KeyMint set-version request");
	build_keymaster_date_support_request(date_support_request);
	HMAC_SELFTEST_REQUIRE(!memcmp(date_support_request,
					       expected_date_support_request,
					       sizeof(date_support_request)),
				      "build exact Keymaster date-support request");
	build_keymaster_configure_request(configure_request);
	HMAC_SELFTEST_REQUIRE(!memcmp(configure_request,
					       expected_configure_request,
					       sizeof(configure_request)),
				      "build exact Piano configure request");

	build_keymaster_hmac_request(keymaster_request_data);
	HMAC_SELFTEST_REQUIRE(!memcmp(keymaster_request_data,
					       expected_keymaster_hmac_request,
					       sizeof(keymaster_request_data)),
				      "build exact direct private-HMAC request");
	memcpy(keymaster_request_output_data, keymaster_request_data,
	       sizeof(keymaster_request_output_data));
	memset(keymaster_response_data, 0xa5, sizeof(keymaster_response_data));
	write_le32(keymaster_response_data, 0);
	write_le32(keymaster_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(keymaster_response_data + KEYMASTER_HMAC_LENGTH_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - KEYMASTER_HMAC_HEADER_SIZE);
	HMAC_SELFTEST_REQUIRE(!validate_keymaster_hmac_response(
				&keymaster_request, &keymaster_request_output,
				&keymaster_response),
				      "accept valid Keymaster response");

	for (i = 0; i < KEYMASTER_HMAC_RESPONSE_SIZE; i++) {
		keymaster_response.size = i;
		HMAC_SELFTEST_REQUIRE(
			validate_keymaster_hmac_response_only_common(
				&keymaster_response, false) == -EPROTO,
			"reject every short direct private-HMAC response");
	}
	keymaster_response.size = KEYMASTER_HMAC_RESPONSE_SIZE + 1U;
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_hmac_response_only_common(
			&keymaster_response, false) == -EPROTO,
		"reject an oversized direct private-HMAC response");
	keymaster_response.size = sizeof(uint32_t);
	write_le32(keymaster_response_data, 1);
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_hmac_response_only_common(
			&keymaster_response, false) == -EREMOTEIO,
		"return a direct private-HMAC business status before size checks");
	keymaster_response.size = KEYMASTER_HMAC_RESPONSE_SIZE;
	write_le32(keymaster_response_data, 0);

	write_le32(keymaster_response_data, 1);
	HMAC_SELFTEST_REQUIRE(validate_keymaster_hmac_response(
				&keymaster_request, &keymaster_request_output,
				&keymaster_response) == -EREMOTEIO,
			      "reject nonzero Keymaster status");
	write_le32(keymaster_response_data, 0);

	write_le32(keymaster_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE - 1U);
	HMAC_SELFTEST_REQUIRE(validate_keymaster_hmac_response(
				&keymaster_request, &keymaster_request_output,
				&keymaster_response) == -EPROTO,
			      "reject message offset inside Keymaster header");

	write_le32(keymaster_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(keymaster_response_data + KEYMASTER_HMAC_LENGTH_OFFSET, 0);
	HMAC_SELFTEST_REQUIRE(validate_keymaster_hmac_response(
				&keymaster_request, &keymaster_request_output,
				&keymaster_response) == -EPROTO,
			      "reject empty encapsulated message");

	write_le32(keymaster_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - 4U);
	write_le32(keymaster_response_data + KEYMASTER_HMAC_LENGTH_OFFSET, 8);
	HMAC_SELFTEST_REQUIRE(validate_keymaster_hmac_response(
				&keymaster_request, &keymaster_request_output,
				&keymaster_response) == -EPROTO,
			      "reject encapsulated message extending past response");
	write_le32(keymaster_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(keymaster_response_data + KEYMASTER_HMAC_LENGTH_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - KEYMASTER_HMAC_HEADER_SIZE);

	keymaster_response.size--;
	HMAC_SELFTEST_REQUIRE(validate_keymaster_hmac_response(
				&keymaster_request, &keymaster_request_output,
				&keymaster_response) == -EPROTO,
			      "reject truncated Keymaster response");
	keymaster_response.size++;

	keymaster_request_output_data[0] ^= 1U;
	HMAC_SELFTEST_REQUIRE(validate_keymaster_hmac_response(
				&keymaster_request, &keymaster_request_output,
				&keymaster_response) == -EPROTO,
				      "reject modified Keymaster request");
	keymaster_request_output_data[0] ^= 1U;
	keymaster_request_output.size--;
	HMAC_SELFTEST_REQUIRE(validate_keymaster_hmac_response(
					&keymaster_request, &keymaster_request_output,
					&keymaster_response) == -EPROTO,
				      "reject truncated direct private-HMAC request output");
	keymaster_request_output.size++;

	memset(service_hmac_response_data, 0xa5,
	       sizeof(service_hmac_response_data));
	write_le32(service_hmac_response_data, 0);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - KEYMASTER_HMAC_HEADER_SIZE);
	HMAC_SELFTEST_REQUIRE(
		!validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false),
		"accept fixed private-HMAC view in capacity-sized service output");
	HMAC_SELFTEST_REQUIRE(
		service_hmac_response_data[KEYMASTER_HMAC_RESPONSE_SIZE] == 0xa5 &&
		service_hmac_response_data[
			sizeof(service_hmac_response_data) - 1U] == 0xa5,
		"ignore service transport bytes after the fixed private-HMAC view");

	write_le32(service_hmac_response_data, 0);
	for (i = 0; i < KEYMASTER_HMAC_RESPONSE_SIZE; i++) {
		service_hmac_response.size = i;
		HMAC_SELFTEST_REQUIRE(
			validate_keymaster_service_hmac_response_common(
				&service_hmac_response, false) == -EPROTO,
			"reject every service output size below 0x100");
	}
	service_hmac_response.size = sizeof(uint32_t);
	write_le32(service_hmac_response_data, 1);
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false) == -EREMOTEIO,
		"return a four-byte private-HMAC business status before size checks");

	service_hmac_response.size = sizeof(service_hmac_response_data);
	write_le32(service_hmac_response_data, 0);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - sizeof(uint32_t));
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET,
		   2U * sizeof(uint32_t));
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false) == -EPROTO,
		"reject a private message crossing 0x100 inside service capacity");

	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - 1U);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET, 1);
	HMAC_SELFTEST_REQUIRE(
		!validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false),
		"accept a one-byte private message ending exactly at 0x100");
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET, 2);
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false) == -EPROTO,
		"reject a private message starting at 0xff and crossing 0x100");

	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET, 1);
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false) == -EPROTO,
		"reject a nonempty private message starting at 0x100");
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   UINT32_MAX);
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false) == -EPROTO,
		"reject a UINT32_MAX private-message offset without underflow");
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET,
		   UINT32_MAX);
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false) == -EPROTO,
		"reject a UINT32_MAX private-message length without overflow");

	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(service_hmac_response_data, 1);
	HMAC_SELFTEST_REQUIRE(
		validate_keymaster_service_hmac_response_common(
			&service_hmac_response, false) == -EREMOTEIO,
		"ignore a plausible private header after a capacity-sized error status");
	write_le32(service_hmac_response_data, 0);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_OFFSET_OFFSET,
		   KEYMASTER_HMAC_HEADER_SIZE);
	write_le32(service_hmac_response_data + KEYMASTER_HMAC_LENGTH_OFFSET,
		   KEYMASTER_HMAC_RESPONSE_SIZE - KEYMASTER_HMAC_HEADER_SIZE);

	memset(service_hmac_response_data, 0xa5,
	       sizeof(service_hmac_response_data));
	secure_clear(service_hmac_response_data,
		     sizeof(service_hmac_response_data));
	HMAC_SELFTEST_REQUIRE(
		bytes_are_zero(service_hmac_response_data,
			       sizeof(service_hmac_response_data)),
		"clear the complete 0x9ff8 private-HMAC service owner");

	build_gfpia_hmac_request(gfpia_request_data, request_time, log_level);
	write_le32(expected_gfpia_request + 0x08, GFPIA_HMAC_TOKEN);
	write_le32(expected_gfpia_request + 0x0c, GFPIA_HMAC_CLASS);
	write_le64(expected_gfpia_request + 0x10, request_time);
	write_le32(expected_gfpia_request + 0x18, log_level);
	write_le32(expected_gfpia_request + 0x20, GFPIA_109_COMMAND);
	write_le32(expected_gfpia_request + 0x24, GFPIA_109_PAYLOAD_SIZE);
	HMAC_SELFTEST_REQUIRE(!memcmp(gfpia_request_data,
				       expected_gfpia_request,
				       sizeof(gfpia_request_data)),
			      "build exact GFPiA command-109 request");
	HMAC_SELFTEST_REQUIRE(bytes_are_zero(gfpia_request_data + 0x28,
					      GFPIA_REQUEST_SIZE - 0x28),
			      "leave all fields after command-109 size clear");
	memcpy(gfpia_request_output_data, gfpia_request_data,
	       sizeof(gfpia_request_output_data));
	write_le64(gfpia_request_output_data, UINT64_C(0x1000));
	HMAC_SELFTEST_REQUIRE(!validate_gfpia_hmac_result(
				&gfpia_request, &gfpia_request_output,
				&gfpia_response),
			      "accept valid GFPiA command-109 response");

	gfpia_response.size--;
	HMAC_SELFTEST_REQUIRE(validate_gfpia_hmac_result(
				&gfpia_request, &gfpia_request_output,
				&gfpia_response) == -EPROTO,
			      "reject truncated GFPiA command-109 response");
	gfpia_response.size++;

	gfpia_request_output_data[0x28] = 1;
	HMAC_SELFTEST_REQUIRE(validate_gfpia_hmac_result(
				&gfpia_request, &gfpia_request_output,
				&gfpia_response) == -EPROTO,
			      "reject modified GFPiA command-109 fields");
	gfpia_request_output_data[0x28] = 0;

	write_le32(gfpia_response_data, 1);
	HMAC_SELFTEST_REQUIRE(validate_gfpia_hmac_result(
				&gfpia_request, &gfpia_request_output,
				&gfpia_response) == -EREMOTEIO,
			      "reject nonzero GFPiA command-109 status");
	write_le32(gfpia_response_data, 0);

	write_le64(gfpia_request_output_data, 0);
	HMAC_SELFTEST_REQUIRE(validate_gfpia_hmac_result(
				&gfpia_request, &gfpia_request_output,
				&gfpia_response) == -ERANGE,
			      "reject null GFPiA command-109 payload address");
	write_le64(gfpia_request_output_data,
		   (uint64_t)UINT32_MAX - GFPIA_109_PAYLOAD_SIZE + 2U);
	HMAC_SELFTEST_REQUIRE(validate_gfpia_hmac_result(
				&gfpia_request, &gfpia_request_output,
				&gfpia_response) == -ERANGE,
			      "reject GFPiA command-109 payload crossing 4 GiB");

	memset(cleared_data, 0xa5, sizeof(cleared_data));
	secure_clear(cleared_data, sizeof(cleared_data));
	HMAC_SELFTEST_REQUIRE(bytes_are_zero(cleared_data,
					      sizeof(cleared_data)),
			      "clear sensitive buffers");

	ret = 0;
	secure_clear(keymaster_request_data, sizeof(keymaster_request_data));
	secure_clear(keymaster_request_output_data,
		     sizeof(keymaster_request_output_data));
	secure_clear(keymaster_response_data, sizeof(keymaster_response_data));
	secure_clear(service_hmac_response_data,
		     sizeof(service_hmac_response_data));
	secure_clear(gfpia_request_data, sizeof(gfpia_request_data));
	secure_clear(gfpia_request_output_data,
		     sizeof(gfpia_request_output_data));
	secure_clear(gfpia_response_data, sizeof(gfpia_response_data));
	secure_clear(expected_gfpia_request, sizeof(expected_gfpia_request));
	secure_clear(cleared_data, sizeof(cleared_data));
	secure_clear(keymint_version_request, sizeof(keymint_version_request));
	secure_clear(date_support_request, sizeof(date_support_request));
	secure_clear(configure_request, sizeof(configure_request));
	puts("qcomtee-qseecom Keymaster/HMAC self-test: PASS");
	return ret;
}

#undef HMAC_SELFTEST_REQUIRE

static int send_gfpia_sequence(int tee_fd, struct qtee_object controller,
			       char **argv, bool hlos_init, bool finish_init)
{
	struct gfpia_step steps[3];
	const size_t step_count = finish_init ? ARRAY_SIZE(steps) : 2;
	const uint8_t fw_info = XIAOMI_FP_FW_INFO;
	size_t i;
	int ret;

	if (finish_init && !hlos_init)
		return -EINVAL;

	initialize_gfpia_step(&steps[0], "command 1000", GFPIA_1000_COMMAND,
			       GFPIA_CLASS_NORMAL, GFPIA_1000_PAYLOAD_SIZE, 1, 0,
			       GFPIA_MODEL_NONE, 0, argv[6], argv[7], argv[8]);
	initialize_gfpia_step(&steps[1], "command 1001", GFPIA_1001_COMMAND,
			       GFPIA_CLASS_NORMAL, GFPIA_1001_PAYLOAD_SIZE, 2, 1,
			       GFPIA_MODEL_NONE, 0, argv[11], argv[12], argv[13]);
	if (finish_init)
		initialize_gfpia_step(&steps[2], "command 1005",
				       GFPIA_1005_COMMAND, GFPIA_CLASS_NORMAL,
				       GFPIA_1005_PAYLOAD_SIZE,
				       3, 2, GFPIA_MODEL_NONE, 0,
				       argv[16], argv[17], argv[18]);

	for (i = 0; i < step_count; i++) {
		const size_t argument = 4 + i * 5;

		ret = load_gfpia_step(tee_fd, &steps[i], argv[argument],
				      argv[argument + 1]);
		if (ret)
			goto out;
	}
	for (i = 0; i < step_count; i++) {
		ret = prepare_gfpia_step_outputs(&steps[i]);
		if (ret)
			goto out_discard_outputs;
	}

	ret = invoke_gfpia_step(tee_fd, controller, &steps[0], 0);
	if (ret)
		goto out;

	steps[1].shared_payload.data[0x6c] = fw_info;

	ret = invoke_gfpia_step(tee_fd, controller, &steps[1], fw_info);
	if (ret)
		goto out;
	if (hlos_init) {
		ret = validate_gfpia_hlos_gate(&steps[1], fw_info);
		if (ret)
			goto out;
	}
	if (finish_init)
		ret = invoke_gfpia_step(tee_fd, controller, &steps[2], 0);

	goto out;

out_discard_outputs:
	for (i = 0; i < step_count; i++)
		discard_gfpia_step_outputs(&steps[i]);

out:
	for (i = 0; i < step_count; i++)
		release_gfpia_step(&steps[i]);
	return ret;
}

static int validate_gfpia_piano_config(const struct gfpia_step *step)
{
	const uint8_t *config = step->shared_payload.data + 0x70;
	uint32_t palm_enabled = read_le32(config + 0x17c);
	uint8_t asp_enabled = config[0x19d];
	uint8_t asp_select_t = config[0x1a2];

	fprintf(stdout,
		"Piano config: chip 0x%02x, palm %" PRIu32
		", ASP %u, ASP_T %u\n",
		config[0], palm_enabled, asp_enabled, asp_select_t);
	if (config[0] != 0x31 || palm_enabled != 1 || asp_enabled != 1 ||
	    asp_select_t != 0) {
		fprintf(stderr,
			"Piano model inputs do not match command-1000 feature selection\n");
		return -EPROTO;
	}
	return 0;
}

static int validate_gfpia_directory(const char *path, const char *description)
{
	struct stat status;

	if (stat(path, &status) < 0)
		return report_errno(path);
	if (!S_ISDIR(status.st_mode)) {
		fprintf(stderr, "%s is not a directory: %s\n", description, path);
		return -ENOTDIR;
	}
	return 0;
}

static int build_gfpia_step_path(char *path, size_t size, const char *directory,
				 const char *prefix, const char *stem)
{
	int length;

	length = snprintf(path, size, "%s/%s-%s.bin", directory, prefix, stem);
	if (length < 0 || (size_t)length >= size) {
		fprintf(stderr, "gfpia step path is too long\n");
		return -ENAMETOOLONG;
	}
	return 0;
}

/*
 * The request carries the HAL's idea of the local time of day. The TA logs it;
 * every reader of these files, including this program's own validator, expects
 * milliseconds since local midnight.
 */
static uint64_t milliseconds_since_local_midnight(void)
{
	struct timespec now;
	struct tm local;

	if (clock_gettime(CLOCK_REALTIME, &now) < 0 ||
	    !localtime_r(&now.tv_sec, &local))
		return 0;

	return (uint64_t)local.tm_hour * 3600000 +
	       (uint64_t)local.tm_min * 60000 +
	       (uint64_t)local.tm_sec * 1000 +
	       (uint64_t)(now.tv_nsec / 1000000);
}

/**
 * gfpia_build_request() - Fill in a gfpia modified-command request.
 * @request: GFPIA_REQUEST_SIZE bytes to write.
 * @token: request token; the stock client increments one per request.
 * @command_class: 1 for the HAL's ordinary commands, 3 for the test ones.
 * @command: wire command.
 * @payload_size: the command's own payload length.
 * @request_time: milliseconds since local midnight.
 *
 * The declared length has to be the command's own, not the length of whatever
 * mapping the payload lives in: shared_memory_alloc() hands back a page-rounded
 * size, and a request declaring more than the command has is refused by the TA
 * before it looks at the payload at all.
 */
static void gfpia_build_request(uint8_t *request, uint32_t token,
				uint32_t command_class, uint32_t command,
				uint32_t payload_size, uint64_t request_time)
{
	memset(request, 0, GFPIA_REQUEST_SIZE);
	/* Bytes 0..7 stay zero; QTEE patches the payload address into them. */
	write_le32(request + 0x08, token);
	write_le32(request + 0x0c, command_class);
	write_le64(request + 0x10, request_time);
	write_le32(request + 0x20, command);
	write_le32(request + 0x24, payload_size);
}

/**
 * gfpia_enumerate() - Ask the TA which fingers it holds.
 * @tee_fd: open TEE device.
 * @controller: the loaded gfpia application.
 * @token: request token.
 * @label: what to call this enumeration in the log.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int gfpia_enumerate(int tee_fd, struct qtee_object controller,
			   uint32_t token, const char *label)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	unsigned int found = 0;
	unsigned int i;
	uint32_t auxiliary;
	uint32_t status;
	int ret;

	ret = shared_memory_alloc(tee_fd, GFPIA_1015_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_1015_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}
	memset(payload.data, 0, GFPIA_1015_PAYLOAD_SIZE);

	gfpia_build_request(request_data, token, GFPIA_CLASS_NORMAL,
			    GFPIA_1015_COMMAND, GFPIA_1015_PAYLOAD_SIZE,
			    milliseconds_since_local_midnight());

	ret = send_request(tee_fd, controller, &request, &payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		goto out;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		ret = -EPROTO;
		goto out_free;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	fprintf(stdout, "enumerate (%s): status 0x%08" PRIx32
		", auxiliary 0x%08" PRIx32 "\n", label, status, auxiliary);
	if (status || auxiliary) {
		ret = -EREMOTEIO;
		goto out_free;
	}

	for (i = 0; i < GFPIA_ENUMERATE_MAX_FINGERS; i++) {
		uint32_t finger = read_le32(payload.data +
					    GFPIA_ENUMERATE_FINGER_OFFSET +
					    i * sizeof(uint32_t));
		uint32_t group;

		if (!finger)
			continue;
		group = read_le32(payload.data +
				  GFPIA_ENUMERATE_GROUP_OFFSET +
				  i * sizeof(uint32_t));
		fprintf(stdout, "  slot %u: group %" PRIu32 ", finger %" PRIu32
			"\n", i, group, finger);
		found++;
	}
	fprintf(stdout, "enumerate (%s): %u finger(s)\n", label, found);

out_free:
	secure_free_blob(&response);
	secure_free_blob(&request_output);
out:
	shared_memory_release(&payload);

	return ret;
}

/**
 * gfpia_pre_enroll() - Start an enrolment and take the TA's challenge.
 * @tee_fd: open TEE device.
 * @controller: the loaded gfpia application.
 * @token: request token.
 * @challenge: where to leave the challenge the TA returns.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int gfpia_pre_enroll(int tee_fd, struct qtee_object controller,
			    uint32_t token, uint64_t *challenge)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t auxiliary;
	uint32_t status;
	int ret;

	ret = shared_memory_alloc(tee_fd, GFPIA_1006_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_1006_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}
	memset(payload.data, 0, GFPIA_1006_PAYLOAD_SIZE);

	gfpia_build_request(request_data, token, GFPIA_CLASS_NORMAL,
			    GFPIA_1006_COMMAND, GFPIA_1006_PAYLOAD_SIZE,
			    milliseconds_since_local_midnight());

	ret = send_request(tee_fd, controller, &request, &payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		goto out;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		ret = -EPROTO;
		goto out_free;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	*challenge = read_le64(payload.data +
			       GFPIA_PRE_ENROLL_CHALLENGE_OFFSET);
	fprintf(stdout, "pre-enrol: status 0x%08" PRIx32
		", auxiliary 0x%08" PRIx32 ", challenge 0x%016" PRIx64 "\n",
		status, auxiliary, *challenge);
	if (status || auxiliary)
		ret = -EREMOTEIO;

out_free:
	secure_free_blob(&response);
	secure_free_blob(&request_output);
out:
	shared_memory_release(&payload);

	return ret;
}

/**
 * build_hw_auth_token() - Lay out Android's authentication token.
 * @token: GFPIA_AUTH_TOKEN_SIZE bytes to write.
 * @challenge: the challenge pre-enrol returned.
 *
 * The shape is fixed by Android: one version byte, three little-endian 64-bit
 * identifiers, then a big-endian type and timestamp, then the HMAC. Everything
 * a gatekeeper would fill in is left zero.
 */
static void build_hw_auth_token(uint8_t *token, uint64_t challenge)
{
	memset(token, 0, GFPIA_AUTH_TOKEN_SIZE);
	token[0] = 0;                             /* version */
	write_le64(token + 1, challenge);         /* challenge */
	/* user id, authenticator id, type, timestamp and HMAC stay zero. */
}

/**
 * gfpia_enroll() - Start a real enrolment.
 * @tee_fd: open TEE device.
 * @controller: the loaded gfpia application.
 * @token: request token.
 * @group: group to enrol into.
 * @challenge: the challenge pre-enrol returned.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int gfpia_enroll(int tee_fd, struct qtee_object controller,
			uint32_t token, uint32_t group, uint64_t challenge)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t auxiliary;
	uint32_t status;
	int ret;

	ret = shared_memory_alloc(tee_fd, GFPIA_1007_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_1007_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, GFPIA_1007_PAYLOAD_SIZE);
	write_le32(payload.data + GFPIA_ENROLL_GROUP_OFFSET, group);
	payload.data[GFPIA_ENROLL_DUMP_OFFSET] = 0;
	build_hw_auth_token(payload.data + GFPIA_ENROLL_TOKEN_OFFSET,
			    challenge);

	gfpia_build_request(request_data, token, GFPIA_CLASS_NORMAL,
			    GFPIA_1007_COMMAND, GFPIA_1007_PAYLOAD_SIZE,
			    milliseconds_since_local_midnight());

	ret = send_request(tee_fd, controller, &request, &payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		goto out;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		ret = -EPROTO;
		goto out_free;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	fprintf(stdout, "enrol group %" PRIu32 ": status 0x%08" PRIx32
		", auxiliary 0x%08" PRIx32 "\n", group, status, auxiliary);
	if (status || auxiliary)
		ret = -EREMOTEIO;

out_free:
	secure_free_blob(&response);
	secure_free_blob(&request_output);
out:
	shared_memory_release(&payload);

	return ret;
}

/**
 * gfpia_simple_command() - Send a command whose payload is nothing but zeroes.
 * @tee_fd: open TEE device.
 * @controller: the loaded gfpia application.
 * @token: request token.
 * @command: wire command.
 * @label: what to call it in the log.
 *
 * gf_hal_invoke_command_ex() is the stock shape for this: a 0x6c payload from
 * calloc and nothing written into it.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int gfpia_simple_command(int tee_fd, struct qtee_object controller,
				uint32_t token, uint32_t command,
				const char *label)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t auxiliary;
	uint32_t status;
	int ret;

	ret = shared_memory_alloc(tee_fd, GFPIA_COMMON_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_COMMON_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}
	memset(payload.data, 0, GFPIA_COMMON_PAYLOAD_SIZE);

	gfpia_build_request(request_data, token, GFPIA_CLASS_NORMAL, command,
			    GFPIA_COMMON_PAYLOAD_SIZE,
			    milliseconds_since_local_midnight());

	ret = send_request(tee_fd, controller, &request, &payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		goto out;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		ret = -EPROTO;
		goto out_free;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	fprintf(stdout, "%s: status 0x%08" PRIx32 ", auxiliary 0x%08" PRIx32
		"\n", label, status, auxiliary);
	if (status || auxiliary)
		ret = -EREMOTEIO;

out_free:
	secure_free_blob(&response);
	secure_free_blob(&request_output);
out:
	shared_memory_release(&payload);

	return ret;
}

/**
 * gfpia_authenticate() - Ask the TA to match the next finger it sees.
 * @tee_fd: open TEE device.
 * @controller: the loaded gfpia application.
 * @token: request token.
 * @group: group to match against.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int gfpia_authenticate(int tee_fd, struct qtee_object controller,
			      uint32_t token, uint32_t group)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t auxiliary;
	uint32_t status;
	int ret;

	ret = shared_memory_alloc(tee_fd, GFPIA_1010_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_1010_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, GFPIA_1010_PAYLOAD_SIZE);
	write_le32(payload.data + GFPIA_AUTH_GROUP_OFFSET, group);
	write_le64(payload.data + GFPIA_AUTH_OPERATION_OFFSET, 0);
	write_le32(payload.data + GFPIA_AUTH_SENTINEL_OFFSET, UINT32_MAX);

	gfpia_build_request(request_data, token, GFPIA_CLASS_NORMAL,
			    GFPIA_1010_COMMAND, GFPIA_1010_PAYLOAD_SIZE,
			    milliseconds_since_local_midnight());

	ret = send_request(tee_fd, controller, &request, &payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		goto out;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		ret = -EPROTO;
		goto out_free;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	fprintf(stdout, "authenticate group %" PRIu32 ": status 0x%08" PRIx32
		", auxiliary 0x%08" PRIx32 "\n", group, status, auxiliary);
	if (status || auxiliary)
		ret = -EREMOTEIO;

out_free:
	secure_free_blob(&response);
	secure_free_blob(&request_output);
out:
	shared_memory_release(&payload);

	return ret;
}

/**
 * gfpia_save_finger() - Ask the TA to store the finger it has been building.
 * @tee_fd: open TEE device.
 * @controller: the loaded gfpia application.
 * @token: request token.
 * @group: group the TA named in the interrupt payload.
 * @finger: finger the TA named in the interrupt payload.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int gfpia_save_finger(int tee_fd, struct qtee_object controller,
			     uint32_t token, uint32_t group, uint32_t finger)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t auxiliary;
	uint32_t status;
	int ret;

	ret = shared_memory_alloc(tee_fd, GFPIA_1012_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_1012_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, GFPIA_1012_PAYLOAD_SIZE);
	write_le32(payload.data + GFPIA_SAVE_GROUP_OFFSET, group);
	write_le32(payload.data + GFPIA_SAVE_FINGER_OFFSET, finger);

	gfpia_build_request(request_data, token, GFPIA_CLASS_NORMAL,
			    GFPIA_1012_COMMAND, GFPIA_1012_PAYLOAD_SIZE,
			    milliseconds_since_local_midnight());

	ret = send_request(tee_fd, controller, &request, &payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		goto out;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		ret = -EPROTO;
		goto out_free;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	fprintf(stdout, "save group %" PRIu32 " finger %" PRIu32
		": status 0x%08" PRIx32 ", auxiliary 0x%08" PRIx32 "\n",
		group, finger, status, auxiliary);
	if (status || auxiliary)
		ret = -EREMOTEIO;

out_free:
	secure_free_blob(&response);
	secure_free_blob(&request_output);
out:
	shared_memory_release(&payload);

	return ret;
}

/**
 * gfpia_irq_prepare() - Set up the payload for the first round of an interrupt.
 * @payload: shared memory of at least GFPIA_1016_PAYLOAD_SIZE bytes.
 *
 * hal_milan_irq() callocs the payload and writes only these four fields. In
 * particular it leaves the sequence at 0x44 zero, unlike every command the HAL
 * sends outside the interrupt path.
 */
static void gfpia_irq_prepare(struct qtee_shared_memory *payload)
{
	memset(payload->data, 0, GFPIA_1016_PAYLOAD_SIZE);
	write_le32(payload->data + GFPIA_IRQ_STATE_OFFSET,
		   GFPIA_IRQ_STATE_START);
	write_le32(payload->data + GFPIA_IRQ_MODE_OFFSET, GFPIA_IRQ_MODE_VALUE);
	write_le32(payload->data + GFPIA_IRQ_IMAGE_OFFSET,
		   GFPIA_IRQ_IMAGE_VALUE);
	payload->data[GFPIA_IRQ_DUMP_OFFSET] = 0;
}

/**
 * gfpia_irq_state_wants_more() - Does this state ask for another round?
 * @state: the state the TA left at GFPIA_IRQ_STATE_OFFSET.
 *
 * Return: %true when hal_milan_irq() would send GF_CMD_IRQ again.
 */
static bool gfpia_irq_state_wants_more(uint32_t state)
{
	return state == GFPIA_IRQ_STATE_EVENT ||
	       state == GFPIA_IRQ_STATE_AGAIN_FIRST ||
	       state == GFPIA_IRQ_STATE_AGAIN_SECOND ||
	       state == GFPIA_IRQ_STATE_FRAME;
}

/**
 * gfpia_irq_round() - Hand the TA one sensor interrupt.
 * @tee_fd: open TEE device.
 * @controller: the loaded gfpia application.
 * @token: request token, incremented by the caller for every request.
 * @payload: shared memory of GFPIA_1016_PAYLOAD_SIZE bytes.
 * @request_time: milliseconds since local midnight.
 * @ta_status: where to put the TA status the response carries.
 * @ta_auxiliary: where to put the transport error the response carries.
 *
 * Rebuilds the request and sends GF_CMD_IRQ. The payload is left exactly as
 * the caller set it up, because a follow-up round has to hand the TA back the
 * buffer it just wrote.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int gfpia_irq_round(int tee_fd, struct qtee_object controller,
			   uint32_t token, struct qtee_shared_memory *payload,
			   uint64_t request_time, uint32_t *ta_status,
			   uint32_t *ta_auxiliary)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE] = { 0 };
	struct blob request = { request_data, sizeof(request_data) };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t status;
	uint32_t auxiliary;
	int ret;

	gfpia_build_request(request_data, token, GFPIA_CLASS_NORMAL,
			    GFPIA_1016_COMMAND, GFPIA_1016_PAYLOAD_SIZE,
			    request_time);

	ret = send_request(tee_fd, controller, &request, payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		return ret;

	if (response.size != GFPIA_RESPONSE_SIZE) {
		secure_free_blob(&response);
		secure_free_blob(&request_output);
		return -EPROTO;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	secure_free_blob(&response);
	secure_free_blob(&request_output);

	*ta_status = status;
	*ta_auxiliary = auxiliary;

	return 0;
}

/*
 * The interrupt word the TA fills in at GFPIA_IRQ_TYPE_OFFSET, named the way
 * gf_strirq() in the stock HAL names it. Only the bits the TA actually sets on
 * this sensor matter, but decoding all of them keeps a surprise readable.
 */
static const char *const gfpia_irq_bit_names[32] = {
	[1] = "FINGER_DOWN",
	[2] = "FINGER_UP",
	[3] = "MENUKEY_DOWN",
	[4] = "MENUKEY_UP",
	[5] = "BACKKEY_DOWN",
	[6] = "BACKKEY_UP",
	[7] = "IMAGE",
	[8] = "RESET",
	[9] = "TMR_IRQ_MNT",
	[10] = "ONE_FRAME_DONE",
	[11] = "ESD_IRQ",
	[12] = "ADC_FIFO_FULL",
	[13] = "ADC_FIFO_HALF",
	[14] = "FDT_REVERSE",
	[15] = "NAV",
	[16] = "FARGO_ERR",
	[17] = "FARGO_ERR_NOT_RESOLVED",
	[18] = "RESET_FIRST",
	[19] = "RESET_FAILED",
	[20] = "ESD_ERR",
	[21] = "NAV_LEFT",
	[22] = "NAV_RIGHT",
	[23] = "NAV_UP",
	[24] = "NAV_DOWN",
	[25] = "PRESS_LIGHT",
	[26] = "PRESS_HEAVY",
	[27] = "UPDATE_BASE",
	[28] = "TEMPERATURE_CHANGE",
	[31] = "ERR_CHECKSUM",
};

static void print_gfpia_irq_bits(uint32_t type)
{
	const char *separator = "";
	unsigned int bit;

	if (!type) {
		fputs(" none", stdout);
		return;
	}

	for (bit = 0; bit < 32; bit++) {
		if (!(type & (UINT32_C(1) << bit)))
			continue;
		if (gfpia_irq_bit_names[bit])
			fprintf(stdout, "%s %s", separator,
				gfpia_irq_bit_names[bit]);
		else
			fprintf(stdout, "%s bit%u", separator, bit);
		separator = " |";
	}
}

static void report_gfpia_irq(const struct qtee_shared_memory *payload,
			     unsigned int round, uint32_t status,
			     uint32_t auxiliary)
{
	uint32_t type = read_le32(payload->data + GFPIA_IRQ_TYPE_OFFSET);

	fprintf(stdout,
		"irq %u: status 0x%08" PRIx32 " auxiliary 0x%08" PRIx32
		" operation %" PRIu32 " progress %" PRIu16
		" finger %" PRIu32 " result %" PRIu32 " state %" PRIu32
		" type 0x%08" PRIx32 ":",
		round, status, auxiliary,
		read_le32(payload->data + GFPIA_IRQ_OPERATION_OFFSET),
		read_le16(payload->data + GFPIA_IRQ_PROGRESS_OFFSET),
		read_le32(payload->data + GFPIA_IRQ_SAVE_FINGER_OFFSET),
		read_le32(payload->data + GFPIA_IRQ_RESULT_OFFSET),
		read_le32(payload->data + GFPIA_IRQ_STATE_OFFSET), type);
	print_gfpia_irq_bits(type);
	fputc('\n', stdout);
	fflush(stdout);
}

/**
 * dump_gfpia_irq_payload() - Keep one interrupt round's payload.
 * @directory: where to write it.
 * @round: round number, used in the file name.
 * @payload: the buffer the TA has just written.
 *
 * Which fields carry enrolment progress on the untrusted path is not something
 * the HAL reveals: it forwards what it reads to a factory-test app and never
 * asks the TA again. Keeping every round lets the fields that move be found by
 * comparing them.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int dump_gfpia_irq_payload(const char *directory, unsigned int round,
				  const struct qtee_shared_memory *payload)
{
	struct blob whole = { payload->data, GFPIA_1016_PAYLOAD_SIZE };
	char path[PATH_MAX];
	int length;

	length = snprintf(path, sizeof(path), "%s/irq-%03u.bin", directory,
			  round);
	if (length < 0 || (size_t)length >= sizeof(path)) {
		fprintf(stderr, "interrupt payload path is too long\n");
		return -ENAMETOOLONG;
	}

	return write_file(path, &whole);
}

/**
 * run_gfpia_irq_loop() - Feed sensor interrupts to the TA and report what it says.
 * @tee_fd: open TEE device.
 * @fp_fd: open fingerprint control device, with its interrupt enabled.
 * @controller: the loaded gfpia application.
 * @token: request token to use next; left one past the last request sent.
 * @seconds: how long to keep listening.
 * @output_directory: where each round's payload is kept.
 * @save_group: where to leave the group the TA last named.
 * @save_finger: where to leave the finger the TA last named; zero if it never
 *               named one, which is what a refused image looks like.
 *
 * The stock HAL runs this from a thread: read the interrupt, send GF_CMD_IRQ,
 * and act on the fields the TA fills in. While the TA answers with state 4 or
 * 5 it wants the command again before the interrupt is considered handled.
 *
 * Return: Zero on success, < 0 on failure.
 */
static int run_gfpia_irq_loop(int tee_fd, int fp_fd,
			      struct qtee_object controller, uint32_t *token,
			      unsigned int seconds,
			      const char *output_directory,
			      uint32_t *save_group, uint32_t *save_finger)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	unsigned int round = 0;
	bool complete = false;
	time_t deadline;
	int ret;

	ret = shared_memory_alloc(tee_fd, GFPIA_1016_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_1016_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	fprintf(stdout,
		"listening for sensor interrupts for %u seconds; touch the sensor\n",
		seconds);
	fflush(stdout);

	deadline = time(NULL) + (time_t)seconds;
	for (;;) {
		struct pollfd fds = { .fd = fp_fd, .events = POLLIN };
		time_t now = time(NULL);
		uint32_t state;
		/* UIO hands over the event counter and refuses any other length. */
		uint32_t event;
		int remaining;
		int ready;

		if (complete || now >= deadline)
			break;
		remaining = (int)(deadline - now) * 1000;

		ready = poll(&fds, 1, remaining);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			ret = report_errno("poll fingerprint device");
			goto out;
		}
		if (!ready)
			break;
		if (read(fp_fd, &event, sizeof(event)) !=
		    (ssize_t)sizeof(event)) {
			if (errno == EINTR)
				continue;
			ret = report_errno("read fingerprint interrupt");
			goto out;
		}

		/*
		 * One interrupt can take more than one round: the TA asks for
		 * the command again by leaving state at 4 or 5.
		 */
		gfpia_irq_prepare(&payload);
		for (unsigned int again = 0; again < GFPIA_IRQ_MAX_ROUNDS;
		     again++) {
			uint32_t auxiliary = 0;
			uint32_t status = 0;
			uint32_t finger;

			ret = gfpia_irq_round(tee_fd, controller, *token,
					      &payload,
					      milliseconds_since_local_midnight(),
					      &status, &auxiliary);
			if (ret)
				goto out;
			(*token)++;
			report_gfpia_irq(&payload, ++round, status, auxiliary);
			ret = dump_gfpia_irq_payload(output_directory, round,
						     &payload);
			if (ret)
				goto out;

			finger = read_le32(payload.data +
					   GFPIA_IRQ_SAVE_FINGER_OFFSET);
			if (finger) {
				*save_finger = finger;
				*save_group = read_le32(payload.data +
						GFPIA_IRQ_SAVE_GROUP_OFFSET);
			}

			/*
			 * A rejected round says nothing about the next one, so
			 * keep the window open and let the evidence accumulate.
			 */
			if (status || auxiliary)
				break;

			/*
			 * An enrolment is finished the moment the TA stops
			 * asking for images. Waiting out the rest of the
			 * window would only risk starting something else.
			 */
			if (!status &&
			    (read_le32(payload.data + GFPIA_IRQ_TYPE_OFFSET) &
			     GFPIA_IRQ_TYPE_IMAGE) &&
			    read_le32(payload.data +
				      GFPIA_IRQ_OPERATION_OFFSET) ==
			    GFPIA_IRQ_OPERATION_ENROL &&
			    !read_le16(payload.data +
				       GFPIA_IRQ_PROGRESS_OFFSET)) {
				fprintf(stdout, "enrolment complete\n");
				complete = true;
			}

			state = read_le32(payload.data + GFPIA_IRQ_STATE_OFFSET);
			if (!gfpia_irq_state_wants_more(state))
				break;
			if (state == GFPIA_IRQ_STATE_FRAME)
				memset(payload.data + GFPIA_IRQ_FRAME_OFFSET, 0,
				       GFPIA_IRQ_FRAME_SIZE);
		}
		if (complete)
			break;
	}

	fprintf(stdout, "interrupt loop finished after %u rounds\n", round);

out:
	shared_memory_release(&payload);

	return ret;
}

static int send_gfpia_piano_sequence(int tee_fd, int fp_fd,
				     struct qtee_object controller,
				     struct qtee_object loader,
				     const char *input_directory,
				     const char *output_directory,
				     bool set_active_group,
				     bool enroll_probe,
				     bool verify,
				     unsigned int irq_seconds,
				     const char *keymaster_source)
{
	static const struct gfpia_piano_step_spec specs[] = {
		{ "1000", "command 1000", GFPIA_1000_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1000_PAYLOAD_SIZE, 1, 0, GFPIA_MODEL_NONE, 0 },
		{ "1001", "command 1001", GFPIA_1001_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1001_PAYLOAD_SIZE, 2, 1, GFPIA_MODEL_NONE, 0 },
		{ "1113-asp-0", "command 1113 ASP chunk 0", GFPIA_1113_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1113_PAYLOAD_SIZE, 3, 2, GFPIA_MODEL_ASP, 0 },
		{ "1113-asp-1", "command 1113 ASP chunk 1", GFPIA_1113_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1113_PAYLOAD_SIZE, 4, 3, GFPIA_MODEL_ASP, 1 },
		{ "1113-asp-2", "command 1113 ASP chunk 2", GFPIA_1113_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1113_PAYLOAD_SIZE, 5, 4, GFPIA_MODEL_ASP, 2 },
		{ "1113-palm-0", "command 1113 palm chunk 0", GFPIA_1113_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1113_PAYLOAD_SIZE, 6, 5, GFPIA_MODEL_PALM, 0 },
		{ "1113-palm-1", "command 1113 palm chunk 1", GFPIA_1113_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1113_PAYLOAD_SIZE, 7, 6, GFPIA_MODEL_PALM, 1 },
		{ "1113-palm-2", "command 1113 palm chunk 2", GFPIA_1113_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1113_PAYLOAD_SIZE, 8, 7, GFPIA_MODEL_PALM, 2 },
		{ "1005", "command 1005", GFPIA_1005_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1005_PAYLOAD_SIZE, 9, 8, GFPIA_MODEL_NONE, 0 },
		{ "1014", "command 1014 active group", GFPIA_1014_COMMAND,
		  GFPIA_CLASS_NORMAL,
		  GFPIA_1014_PAYLOAD_SIZE, 10, 9, GFPIA_MODEL_NONE, 0 },
		{ "1060", "command 1060 untrusted enrol", GFPIA_1060_COMMAND,
		  GFPIA_CLASS_TEST,
		  GFPIA_1060_PAYLOAD_SIZE, 11, 10, GFPIA_MODEL_NONE, 0 },
	};
	const size_t step_count = enroll_probe ? ARRAY_SIZE(specs) :
		set_active_group ? GFPIA_PIANO_ACTIVE_GROUP_STEP_COUNT :
		GFPIA_PIANO_INIT_STEP_COUNT;
	struct gfpia_piano_step_paths paths[GFPIA_PIANO_MAX_STEP_COUNT];
	struct gfpia_step steps[GFPIA_PIANO_MAX_STEP_COUNT];
	struct qtee_object keymaster_controller = { .id = TEE_OBJREF_NULL };
	const uint8_t fw_info = XIAOMI_FP_FW_INFO;
	size_t i;
	int cleanup_ret;
	int ret;

	_Static_assert(ARRAY_SIZE(specs) == GFPIA_PIANO_MAX_STEP_COUNT,
		       "Piano sequence must have eleven steps");
	if (keymaster_source && !set_active_group)
		return -EINVAL;
	/* Enrolment only means anything once a group is selected. */
	if (enroll_probe && !set_active_group)
		return -EINVAL;
	/* Interrupts are only worth reading once an operation is running. */
	if (irq_seconds && !enroll_probe && !verify)
		return -EINVAL;
	if (verify && (enroll_probe || !set_active_group || !irq_seconds))
		return -EINVAL;

	ret = validate_gfpia_directory(input_directory, "input directory");
	if (ret)
		return ret;
	ret = validate_gfpia_directory(output_directory, "output directory");
	if (ret)
		return ret;

	for (i = 0; i < step_count; i++) {
		ret = build_gfpia_step_path(paths[i].request,
					     sizeof(paths[i].request),
					     input_directory, "request",
					     specs[i].stem);
		if (ret)
			return ret;
		ret = build_gfpia_step_path(paths[i].payload,
					     sizeof(paths[i].payload),
					     input_directory, "payload",
					     specs[i].stem);
		if (ret)
			return ret;
		ret = build_gfpia_step_path(paths[i].response,
					     sizeof(paths[i].response),
					     output_directory, "response",
					     specs[i].stem);
		if (ret)
			return ret;
		ret = build_gfpia_step_path(paths[i].payload_output,
					     sizeof(paths[i].payload_output),
					     output_directory, "payload-out",
					     specs[i].stem);
		if (ret)
			return ret;
		ret = build_gfpia_step_path(paths[i].request_output,
					     sizeof(paths[i].request_output),
					     output_directory, "request-out",
					     specs[i].stem);
		if (ret)
			return ret;
	}

	for (i = 0; i < step_count; i++) {
		initialize_gfpia_step(&steps[i], specs[i].label,
				       specs[i].command, specs[i].command_class,
				       specs[i].payload_size,
				       specs[i].token, specs[i].sequence,
				       specs[i].model_kind, specs[i].model_chunk,
				       paths[i].response, paths[i].payload_output,
				       paths[i].request_output);
	}
	for (i = 0; i < step_count; i++) {
		ret = load_gfpia_step(tee_fd, &steps[i], paths[i].request,
				      paths[i].payload);
		if (ret)
			goto out;
	}

	ret = validate_gfpia_piano_model(steps, GFPIA_PIANO_ASP_FIRST_STEP,
					 GFPIA_MODEL_ASP);
	if (ret)
		goto out;
	ret = validate_gfpia_piano_model(steps, GFPIA_PIANO_PALM_FIRST_STEP,
					 GFPIA_MODEL_PALM);
	if (ret)
		goto out;

	for (i = 0; i < step_count; i++) {
		ret = prepare_gfpia_step_outputs(&steps[i]);
		if (ret)
			goto out_discard_outputs;
	}
	if (keymaster_source) {
		ret = start_app(tee_fd, loader, KEYMASTER_APP_NAME,
				keymaster_source, &keymaster_controller);
		if (ret)
			goto out;
		fprintf(stdout, "keymaster64 controller object: %" PRIu64 "\n",
			keymaster_controller.id);
	}

	ret = invoke_gfpia_step(tee_fd, controller, &steps[0], 0);
	if (ret)
		goto out;
	ret = validate_gfpia_piano_config(&steps[0]);
	if (ret)
		goto out;

	steps[1].shared_payload.data[0x6c] = fw_info;

	ret = invoke_gfpia_step(tee_fd, controller, &steps[1], fw_info);
	if (ret)
		goto out;
	ret = validate_gfpia_hlos_gate(&steps[1], fw_info);
	if (ret)
		goto out;

	for (i = GFPIA_PIANO_ASP_FIRST_STEP;
	     i < GFPIA_PIANO_1005_STEP; i++) {
		ret = invoke_gfpia_step(tee_fd, controller, &steps[i], 0);
		if (ret)
			goto out;
	}
	ret = invoke_gfpia_step(tee_fd, controller,
				&steps[GFPIA_PIANO_1005_STEP], 0);
	if (!ret && set_active_group)
		ret = invoke_gfpia_step(tee_fd, controller,
					&steps[GFPIA_PIANO_ACTIVE_GROUP_STEP], 0);
	if (!ret && verify) {
		uint32_t token =
			specs[GFPIA_PIANO_ENROLL_PROBE_STEP].token + 1;
		uint32_t matched = 0;
		uint32_t group = 0;

		ret = gfpia_enumerate(tee_fd, controller, token++, "stored");
		if (!ret)
			ret = gfpia_authenticate(tee_fd, controller, token++, 0);
		if (!ret)
			ret = run_gfpia_irq_loop(tee_fd, fp_fd, controller,
						 &token, irq_seconds,
						 output_directory, &group,
						 &matched);
		if (!ret && matched)
			fprintf(stdout, "matched finger %" PRIu32
				" in group %" PRIu32 "\n", matched, group);
		else if (!ret)
			fprintf(stdout, "no finger matched\n");
	}
	if (!ret && enroll_probe) {
		uint32_t token =
			specs[GFPIA_PIANO_ENROLL_PROBE_STEP].token + 1;


		/*
		 * Enumerate on both sides of the enrolment: what the TA holds
		 * before it, and what it holds afterwards. The difference is
		 * the only evidence that anything was stored.
		 */
		uint32_t save_finger = 0;
		uint32_t save_group = 0;
		uint64_t challenge = 0;

		ret = gfpia_enumerate(tee_fd, controller, token++, "before");
		/*
		 * The stock order is pre-enrol, enrol, capture, save. Skipping
		 * pre-enrol leaves the TA's enrolment count wherever it was.
		 */
		if (!ret)
			ret = gfpia_pre_enroll(tee_fd, controller, token++,
					       &challenge);
		/*
		 * Untrusted enrolment captures and scores images but builds
		 * nothing to save: its results reach a factory-test app and
		 * the HAL's own dispatcher ignores the operation entirely.
		 * A real enrolment goes through command 1007.
		 */
		if (!ret)
			ret = gfpia_enroll(tee_fd, controller, token++, 0,
					   challenge);
		if (!ret && irq_seconds)
			ret = run_gfpia_irq_loop(tee_fd, fp_fd, controller,
						 &token, irq_seconds,
						 output_directory, &save_group,
						 &save_finger);
		if (!ret && irq_seconds)
			ret = gfpia_simple_command(tee_fd, controller, token++,
						   GFPIA_1008_COMMAND,
						   "post-enrol");
		if (!ret && irq_seconds && save_finger)
			ret = gfpia_save_finger(tee_fd, controller, token++,
						save_group, save_finger);
		else if (!ret && irq_seconds)
			fprintf(stdout,
				"the TA named no finger, so there is nothing to save\n");
		if (!ret)
			ret = gfpia_enumerate(tee_fd, controller, token++,
					      "after");
	}
	if (!ret && keymaster_source)
		ret = send_gfpia_hmac_key(
			tee_fd, controller, &keymaster_controller,
			read_le64(steps[GFPIA_PIANO_ACTIVE_GROUP_STEP].request.data +
				  0x10),
			read_le32(steps[GFPIA_PIANO_ACTIVE_GROUP_STEP].request.data +
				  0x18));

	goto out;

out_discard_outputs:
	for (i = 0; i < step_count; i++)
		discard_gfpia_step_outputs(&steps[i]);
out:
	cleanup_ret = object_release(tee_fd, &keymaster_controller);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	for (i = 0; i < step_count; i++)
		release_gfpia_step(&steps[i]);
	return ret;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
			"usage:\n"
			"  %s self-test-hmac\n"
			"  %s probe\n"
			"  %s probe-keymaster-service-version\n"
				"  %s probe-keymaster-service-init\n"
				"  %s probe-keymaster-service-keymint-version\n"
					"  %s probe-keymaster-service-date-support\n"
					"  %s probe-keymaster-service-configure\n"
						"  %s probe-keymaster-service-shared-hmac\n"
						"  %s probe-keymaster-service-shared-hmac-private\n"
						"  %s probe-keymaster-service-shared-hmac-direct-private "
						"keymaster64 SOURCE\n"
				"  %s probe-keymaster-hmac keymaster64 SOURCE\n"
			"  %s lookup APP\n"
			"  %s load APP SOURCE [--hold]\n"
			"  %s send APP SOURCE|- REQUEST RESPONSE [RESPONSE_SIZE]\n"
			"  %s send-modified APP SOURCE|- REQUEST PAYLOAD RESPONSE "
			"PAYLOAD_OUT [RESPONSE_SIZE [REQUEST_OUT]]\n"
			"  %s send-gfpia-1000-1001 gfpia SOURCE "
			"REQ1000 PAY1000 RESP1000 PAYOUT1000 REQOUT1000 "
			"REQ1001 PAY1001 RESP1001 PAYOUT1001 REQOUT1001 "
			"[--hlos-init]\n"
			"  %s send-gfpia-1000-1001-1005 gfpia SOURCE "
			"REQ1000 PAY1000 RESP1000 PAYOUT1000 REQOUT1000 "
			"REQ1001 PAY1001 RESP1001 PAYOUT1001 REQOUT1001 "
			"REQ1005 PAY1005 RESP1005 PAYOUT1005 REQOUT1005\n"
			"  %s send-gfpia-piano-init gfpia SOURCE "
			"INPUT_DIRECTORY OUTPUT_DIRECTORY\n"
			"  %s send-gfpia-piano-active-group gfpia SOURCE "
			"INPUT_DIRECTORY OUTPUT_DIRECTORY\n"
			"  %s send-gfpia-piano-hmac gfpia SOURCE "
			"INPUT_DIRECTORY OUTPUT_DIRECTORY KEYMASTER_SOURCE\n"
			"  %s send-gfpia-piano-enroll-probe gfpia SOURCE "
			"INPUT_DIRECTORY OUTPUT_DIRECTORY\n"
			"  %s send-gfpia-piano-enroll-run gfpia SOURCE "
			"INPUT_DIRECTORY OUTPUT_DIRECTORY SECONDS\n"
			"  %s send-gfpia-piano-verify gfpia SOURCE "
			"INPUT_DIRECTORY OUTPUT_DIRECTORY SECONDS\n"
			"  %s reconstruct APP SOURCE OUTPUT\n",
						program, program, program, program, program,
						program, program, program, program, program,
						program, program, program, program, program,
						program, program, program, program, program,
						program, program, program, program);
}

int main(int argc, char **argv)
{
	struct qtee_object client_env = { .id = TEE_OBJREF_NULL };
	struct qtee_object loader = { .id = TEE_OBJREF_NULL };
	struct qtee_object controller = { .id = TEE_OBJREF_NULL };
	struct blob image = { 0 };
	struct blob request = { 0 };
	struct blob request_output = { 0 };
	struct blob response = { 0 };
	struct blob payload = { 0 };
	struct blob payload_out = { 0 };
	struct qtee_shared_memory shared_payload = {
		.id = -1,
		.fd = -1,
	};
	char device_path[32];
	uint32_t secure_result = 0;
	size_t response_size = DEFAULT_RESPONSE_SIZE;
	bool hold = false;
	bool hlos_init = false;
	bool finish_init = false;
	unsigned int irq_seconds = 0;
	int cleanup_ret;
	int ret = 0;
	int fp_fd = -1;
	int fd;

	if (argc < 2) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	if (strcmp(argv[1], "self-test-hmac") &&
	    strcmp(argv[1], "probe") &&
	    strcmp(argv[1], "probe-keymaster-service-version") &&
		    strcmp(argv[1], "probe-keymaster-service-init") &&
		    strcmp(argv[1], "probe-keymaster-service-keymint-version") &&
			    strcmp(argv[1], "probe-keymaster-service-date-support") &&
			    strcmp(argv[1], "probe-keymaster-service-configure") &&
			    strcmp(argv[1], "probe-keymaster-service-shared-hmac") &&
				    strcmp(argv[1],
					   "probe-keymaster-service-shared-hmac-private") &&
				    strcmp(argv[1],
					   "probe-keymaster-service-shared-hmac-direct-private") &&
		    strcmp(argv[1], "probe-keymaster-hmac") &&
	    strcmp(argv[1], "lookup") &&
	    strcmp(argv[1], "load") && strcmp(argv[1], "send") &&
	    strcmp(argv[1], "send-modified") &&
	    strcmp(argv[1], "send-gfpia-1000-1001") &&
	    strcmp(argv[1], "send-gfpia-1000-1001-1005") &&
	    strcmp(argv[1], "send-gfpia-piano-init") &&
	    strcmp(argv[1], "send-gfpia-piano-active-group") &&
	    strcmp(argv[1], "send-gfpia-piano-hmac") &&
	    strcmp(argv[1], "send-gfpia-piano-enroll-probe") &&
	    strcmp(argv[1], "send-gfpia-piano-enroll-run") &&
	    strcmp(argv[1], "send-gfpia-piano-verify") &&
	    strcmp(argv[1], "reconstruct")) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	if ((!strcmp(argv[1], "self-test-hmac") && argc != 2) ||
	    (!strcmp(argv[1], "probe") && argc != 2) ||
	    (!strcmp(argv[1], "probe-keymaster-service-version") && argc != 2) ||
	    (!strcmp(argv[1], "probe-keymaster-service-init") && argc != 2) ||
		    (!strcmp(argv[1], "probe-keymaster-service-keymint-version") &&
		     argc != 2) ||
		    (!strcmp(argv[1], "probe-keymaster-service-date-support") &&
		     argc != 2) ||
			    (!strcmp(argv[1], "probe-keymaster-service-configure") &&
			     argc != 2) ||
			    (!strcmp(argv[1], "probe-keymaster-service-shared-hmac") &&
			     argc != 2) ||
				    (!strcmp(argv[1],
					     "probe-keymaster-service-shared-hmac-private") &&
				     argc != 2) ||
				    (!strcmp(argv[1],
					     "probe-keymaster-service-shared-hmac-direct-private") &&
				     argc != 4) ||
		    (!strcmp(argv[1], "probe-keymaster-hmac") && argc != 4) ||
	    (!strcmp(argv[1], "lookup") && argc != 3) ||
	    (!strcmp(argv[1], "load") && (argc < 4 || argc > 5)) ||
	    (!strcmp(argv[1], "send") && (argc < 6 || argc > 7)) ||
	    (!strcmp(argv[1], "send-modified") && (argc < 8 || argc > 10)) ||
	    (!strcmp(argv[1], "send-gfpia-1000-1001") &&
	     (argc < 14 || argc > 15)) ||
	    (!strcmp(argv[1], "send-gfpia-1000-1001-1005") && argc != 19) ||
	    (!strcmp(argv[1], "send-gfpia-piano-init") && argc != 6) ||
	    (!strcmp(argv[1], "send-gfpia-piano-active-group") && argc != 6) ||
	    (!strcmp(argv[1], "send-gfpia-piano-hmac") && argc != 7) ||
	    (!strcmp(argv[1], "send-gfpia-piano-enroll-probe") && argc != 6) ||
	    (!strcmp(argv[1], "send-gfpia-piano-enroll-run") && argc != 7) ||
	    (!strcmp(argv[1], "send-gfpia-piano-verify") && argc != 7) ||
	    (!strcmp(argv[1], "reconstruct") && argc != 5)) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	if (argc >= 3 && strnlen(argv[2], MAX_APP_NAME_SIZE) == MAX_APP_NAME_SIZE) {
		fprintf(stderr, "APP must be shorter than %u bytes\n",
			MAX_APP_NAME_SIZE);
		return EXIT_FAILURE;
	}
	if (!strcmp(argv[1], "self-test-hmac"))
		return run_hmac_self_test() ? EXIT_FAILURE : EXIT_SUCCESS;
	if ((!strcmp(argv[1], "probe-keymaster-hmac") ||
	     !strcmp(argv[1],
		     "probe-keymaster-service-shared-hmac-direct-private")) &&
	    strcmp(argv[2], KEYMASTER_APP_NAME)) {
		fprintf(stderr,
			"the fixed HMAC probe is restricted to keymaster64\n");
		return EXIT_FAILURE;
	}
	if (!strcmp(argv[1], "load") && argc == 5) {
		if (strcmp(argv[4], "--hold")) {
			usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
		hold = true;
	}
	if (!strcmp(argv[1], "send") && argc == 7) {
		ret = parse_size(argv[6], &response_size);
		if (ret) {
			fprintf(stderr, "invalid RESPONSE_SIZE\n");
			return EXIT_FAILURE;
		}
	}
	if (!strcmp(argv[1], "send-modified") && argc >= 9) {
		ret = parse_size(argv[8], &response_size);
		if (ret) {
			fprintf(stderr, "invalid RESPONSE_SIZE\n");
			return EXIT_FAILURE;
		}
	}
	if (!strcmp(argv[1], "send-gfpia-1000-1001") && argc == 15) {
		if (strcmp(argv[14], "--hlos-init")) {
			usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
		hlos_init = true;
	}
	if (!strcmp(argv[1], "send-gfpia-1000-1001-1005")) {
		hlos_init = true;
		finish_init = true;
	}
	if (!strcmp(argv[1], "send-gfpia-piano-enroll-run") ||
	    !strcmp(argv[1], "send-gfpia-piano-verify")) {
		char *end = NULL;
		unsigned long value;

		errno = 0;
		value = strtoul(argv[6], &end, 10);
		if (errno || !end || *end || !value || value > 600) {
			fprintf(stderr,
				"SECONDS must be between 1 and 600\n");
			return EXIT_FAILURE;
		}
		irq_seconds = (unsigned int)value;
	}
	if (!strcmp(argv[1], "send") && !strcmp(argv[2], "gfpia")) {
		fprintf(stderr,
			"plain send is unsafe for gfpia; it requires a memory object "
			"patched at request offset 0\n");
		return EXIT_FAILURE;
	}
	if (!strcmp(argv[1], "send-gfpia-1000-1001") ||
	    !strcmp(argv[1], "send-gfpia-1000-1001-1005") ||
	    !strcmp(argv[1], "send-gfpia-piano-init") ||
	    !strcmp(argv[1], "send-gfpia-piano-active-group") ||
	    !strcmp(argv[1], "send-gfpia-piano-hmac") ||
	    !strcmp(argv[1], "send-gfpia-piano-enroll-probe") ||
	    !strcmp(argv[1], "send-gfpia-piano-enroll-run") ||
	    !strcmp(argv[1], "send-gfpia-piano-verify")) {
		if (strcmp(argv[2], "gfpia")) {
			fprintf(stderr,
				"fixed gfpia sequences are restricted to the gfpia TA\n");
			return EXIT_FAILURE;
		}
		fp_fd = get_inherited_xiaomi_fp_fd();
		if (fp_fd < 0)
			return EXIT_FAILURE;
	}

	if (!strcmp(argv[1], "reconstruct")) {
		ret = load_image_source(argv[3], argv[2], &image);
		if (!ret)
			ret = write_file(argv[4], &image);
		free(image.data);
		if (ret)
			fprintf(stderr, "reconstruction failed: %s (%d)\n",
				strerror(-ret), ret);
		return ret ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	fd = find_qcomtee_device(device_path, sizeof(device_path));
	if (fd < 0) {
		fprintf(stderr, "no QTEE object device found: %s\n", strerror(-fd));
		return EXIT_FAILURE;
	}
	fprintf(stdout, "using %s\n", device_path);
	if (!strcmp(argv[1], "probe")) {
		close(fd);
		return EXIT_SUCCESS;
	}

	ret = get_client_env(fd, &client_env);
	if (ret)
		goto out;
	if (!strcmp(argv[1], "probe-keymaster-service-version") ||
	    !strcmp(argv[1], "probe-keymaster-service-init")) {
		ret = probe_keymaster_service(
			fd, client_env,
			!strcmp(argv[1], "probe-keymaster-service-init"));
		goto out;
	}
	if (!strcmp(argv[1], "probe-keymaster-service-keymint-version")) {
		ret = probe_keymaster_service_keymint_version(fd, client_env);
		goto out;
	}
	if (!strcmp(argv[1], "probe-keymaster-service-date-support")) {
		ret = probe_keymaster_service_date_support(fd, client_env);
		goto out;
	}
	if (!strcmp(argv[1], "probe-keymaster-service-configure")) {
		ret = probe_keymaster_service_configure(fd, client_env);
		goto out;
	}
	if (!strcmp(argv[1], "probe-keymaster-service-shared-hmac")) {
		ret = probe_keymaster_service_shared_hmac(fd, client_env);
		goto out;
	}
	if (!strcmp(argv[1],
			    "probe-keymaster-service-shared-hmac-private")) {
		ret = probe_keymaster_service_shared_hmac_private(fd, client_env);
		goto out;
	}
	if (!strcmp(argv[1],
		    "probe-keymaster-service-shared-hmac-direct-private")) {
		ret = probe_keymaster_service_shared_hmac_direct_private(
			fd, client_env, argv[3]);
		goto out;
	}
	ret = client_env_open(fd, client_env, QSEECOM_COMPAT_APP_LOADER_UID,
			      &loader);
	if (ret)
		goto out;

	if (!strcmp(argv[1], "lookup")) {
		ret = app_loader_lookup(fd, loader, argv[2], &controller,
					&secure_result);
		if (ret)
			goto out;
		if (secure_result == APP_LOADER_ERROR_APP_NOT_LOADED) {
			fprintf(stdout, "QTEE TA %s is not loaded\n", argv[2]);
			ret = -ENOENT;
			goto out;
		}
		if (secure_result == QTEE_OBJECT_ERROR_INVALID) {
			fprintf(stdout,
				"QTEE firmware does not implement lookupTA; state unknown\n");
			ret = -EOPNOTSUPP;
			goto out;
		}
		if (secure_result) {
			fprintf(stderr, "lookupTA failed in QTEE: %" PRIu32 "\n",
				secure_result);
			ret = -EREMOTEIO;
			goto out;
		}
		fprintf(stdout, "QTEE TA %s is loaded (object %" PRIu64 ")\n",
			argv[2], controller.id);
		goto out;
	}

	ret = start_app(fd, loader, argv[2], argv[3], &controller);
	if (ret)
		goto out;
	fprintf(stdout, "QSEECom controller object: %" PRIu64 "\n",
		controller.id);

	if (!strcmp(argv[1], "probe-keymaster-hmac")) {
		struct blob hmac_response = { 0 };

		ret = request_keymaster_hmac(fd, &controller, &hmac_response);
		if (!ret)
			fprintf(stdout, "keymaster64 returned a valid HMAC response\n");
		secure_free_blob(&hmac_response);
	} else if (!strcmp(argv[1], "send-gfpia-1000-1001") ||
	    !strcmp(argv[1], "send-gfpia-1000-1001-1005")) {
		ret = send_gfpia_sequence(fd, controller, argv, hlos_init,
					  finish_init);
	} else if (!strcmp(argv[1], "send-gfpia-piano-init") ||
		   !strcmp(argv[1], "send-gfpia-piano-active-group") ||
		   !strcmp(argv[1], "send-gfpia-piano-hmac") ||
		   !strcmp(argv[1], "send-gfpia-piano-enroll-probe") ||
		   !strcmp(argv[1], "send-gfpia-piano-enroll-run") ||
		   !strcmp(argv[1], "send-gfpia-piano-verify")) {
		bool verify = !strcmp(argv[1], "send-gfpia-piano-verify");
		bool enroll = !strcmp(argv[1], "send-gfpia-piano-enroll-probe") ||
			      !strcmp(argv[1], "send-gfpia-piano-enroll-run");

		ret = send_gfpia_piano_sequence(fd, fp_fd, controller,
						loader, argv[4], argv[5],
						strcmp(argv[1],
						       "send-gfpia-piano-init"),
						enroll, verify, irq_seconds,
						!strcmp(argv[1],
							"send-gfpia-piano-hmac") ?
							argv[6] : NULL);
	} else if (!strcmp(argv[1], "send") ||
		   !strcmp(argv[1], "send-modified")) {
		ret = read_file(argv[4], MAX_IO_BUFFER_SIZE, &request);
		if (ret)
			goto out;
		if (!strcmp(argv[1], "send-modified")) {
			ret = read_file(argv[5], MAX_IO_BUFFER_SIZE, &payload);
			if (ret)
				goto out;
			if (!strcmp(argv[2], "gfpia")) {
				ret = validate_gfpia_modified(&request, &payload,
							      response_size);
				if (ret)
					goto out;
			}
			ret = shared_memory_alloc(fd, payload.size, &shared_payload);
			if (ret)
				goto out;
			memset(shared_payload.data, 0, shared_payload.size);
			memcpy(shared_payload.data, payload.data, payload.size);
		}
		ret = send_request(fd, controller, &request,
				   shared_payload.data ? &shared_payload : NULL,
				   response_size, &request_output, &response);
		if (ret)
			goto out;
		if (!strcmp(argv[1], "send-modified") && argc == 10) {
			ret = write_file(argv[9], &request_output);
			if (ret)
				goto out;
			fprintf(stdout, "wrote %zu patched request bytes to %s\n",
				request_output.size, argv[9]);
		}
		ret = write_file(!strcmp(argv[1], "send-modified") ? argv[6] :
				 argv[5], &response);
		if (!ret)
			fprintf(stdout, "wrote %zu response bytes to %s\n",
				response.size,
				!strcmp(argv[1], "send-modified") ? argv[6] : argv[5]);
		if (!ret && !strcmp(argv[1], "send-modified")) {
			payload_out.data = shared_payload.data;
			payload_out.size = payload.size;
			ret = write_file(argv[7], &payload_out);
			if (!ret)
				fprintf(stdout, "wrote %zu payload bytes to %s\n",
					payload_out.size, argv[7]);
		}
	} else if (hold) {
		struct sigaction action = {
			.sa_handler = handle_signal,
		};

		sigemptyset(&action.sa_mask);
		sigaction(SIGINT, &action, NULL);
		sigaction(SIGTERM, &action, NULL);
		fprintf(stdout, "holding controller object; press Ctrl-C to release\n");
		while (!stop_requested)
			pause();
	}

out:
	free(request.data);
	free(request_output.data);
	free(response.data);
	free(payload.data);
	shared_memory_release(&shared_payload);
	/*
	 * Leave QTEE as it was found, so the next run can load the application
	 * again rather than being told it is already there.
	 */
	if (!hold)
		app_unload(fd, controller);
	cleanup_ret = object_release(fd, &controller);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	cleanup_ret = object_release(fd, &loader);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	cleanup_ret = object_release(fd, &client_env);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	close(fd);
	if (fp_fd >= 0)
		close(fp_fd);
	if (ret)
		fprintf(stderr, "operation failed: %s (%d)\n", strerror(-ret), ret);
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
