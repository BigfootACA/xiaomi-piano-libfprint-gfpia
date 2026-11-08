// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The Goodix gfpia fingerprint application, as it is spoken on a Xiaomi
 * Pad 8 Pro.
 *
 * See qcomtee/goodix-gfpia.md for where the numbers came
 * from. The short version: every command is a 0x80-byte request naming a
 * command and a payload length, with the payload itself in a memory object
 * the application reads and writes in place. Enrolment and matching both
 * report through the interrupt command rather than through the command that
 * started them.
 */

#include "gfpia.h"
#include "gfpia-tee.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/*
 * The sensor's supply, reset line and interrupt reach us as a UIO device.
 * There is no ioctl: opening it powers the sensor and arms the interrupt,
 * closing it puts the sensor back into reset with its rail off, and each
 * interrupt arrives as a four-byte event count from read().
 */
#define XIAOMI_FP_UIO_NAME "xiaomi-fp-uio"
#define XIAOMI_FP_UIO_CLASS "/sys/class/uio"

#define GFPIA_APP_NAME "gfpia"

/*
 * Where the filesystem supplicant keeps what the application asks it to store,
 * and the one file in there that must not be kept.
 *
 * gf_fdt_base.so is the sensor's finger-detect baseline. A stale one stops the
 * sensor reporting fingers at all: initialisation and its reset interrupts
 * still work, but touching it does nothing, and there is no error anywhere to
 * say so. The application rewrites the file on every initialisation, which
 * makes its timestamp look fresh while the contents stay wrong; it only builds
 * a new baseline when the file is missing. There is no command to ask for one,
 * so removing it here is the only way to be sure of a good baseline.
 */
#define GFPIA_STATE_ROOT "/var/lib/xiaomi-fingerprint"
#define GFPIA_DETECT_BASE \
	GFPIA_STATE_ROOT "/data/vendor_de/0/fpdata/gf_fdt_base.so"

/* Every command is one of these, and the answer is always 0x40 bytes. */
#define GFPIA_REQUEST_SIZE 0x80U
#define GFPIA_RESPONSE_SIZE 0x40U
#define GFPIA_CLASS_NORMAL UINT32_C(1)

#define GFPIA_CMD_DETECT_SENSOR UINT32_C(1000)
#define GFPIA_CMD_INIT UINT32_C(1001)
#define GFPIA_CMD_INIT_FINISHED UINT32_C(1005)
#define GFPIA_CMD_PRE_ENROL UINT32_C(1006)
#define GFPIA_CMD_ENROL UINT32_C(1007)
#define GFPIA_CMD_POST_ENROL UINT32_C(1008)
#define GFPIA_CMD_CANCEL UINT32_C(1009)
#define GFPIA_CMD_AUTHENTICATE UINT32_C(1010)
#define GFPIA_CMD_SAVE UINT32_C(1012)
#define GFPIA_CMD_REMOVE UINT32_C(1013)
#define GFPIA_CMD_SET_ACTIVE_GROUP UINT32_C(1014)
#define GFPIA_CMD_ENUMERATE UINT32_C(1015)
#define GFPIA_CMD_IRQ UINT32_C(1016)
#define GFPIA_CMD_TRANSPORT_DATA UINT32_C(1113)

#define GFPIA_COMMON_PAYLOAD_SIZE 0x6cU
#define GFPIA_PRE_ENROL_PAYLOAD_SIZE 0x78U
#define GFPIA_ENROL_PAYLOAD_SIZE 0xbcU
#define GFPIA_AUTHENTICATE_PAYLOAD_SIZE 0x80U
#define GFPIA_SAVE_PAYLOAD_SIZE 0x78U
#define GFPIA_REMOVE_PAYLOAD_SIZE 0xccU
#define GFPIA_ENUMERATE_PAYLOAD_SIZE 0xc0U
#define GFPIA_IRQ_PAYLOAD_SIZE 0xd134U

/* Fields the application fills in, common to every command. */
#define GFPIA_OFF_ERROR 0x0cU
#define GFPIA_OFF_SEQUENCE 0x44U

/* Pre-enrol returns the challenge an enrolment token has to be built over. */
#define GFPIA_OFF_CHALLENGE 0x70U

/* Enrol: a group, a dump flag, and Android's authentication token. */
#define GFPIA_OFF_ENROL_GROUP 0x6cU
#define GFPIA_OFF_ENROL_DUMP 0x74U
#define GFPIA_OFF_ENROL_TOKEN 0x76U
#define GFPIA_AUTH_TOKEN_SIZE 69U

/* Authenticate: a group, an operation identifier, and a word of all ones. */
#define GFPIA_OFF_AUTH_GROUP 0x6cU
#define GFPIA_OFF_AUTH_OPERATION 0x70U
#define GFPIA_OFF_AUTH_SENTINEL 0x78U

/* Save and remove both name a group and a finger. */
#define GFPIA_OFF_SAVE_GROUP 0x6cU
#define GFPIA_OFF_SAVE_FINGER 0x70U

/* Enumerate answers with two parallel arrays; a zero finger is an empty slot. */
#define GFPIA_OFF_ENUM_GROUP 0x70U
#define GFPIA_OFF_ENUM_FINGER 0x98U

/* What the interrupt command reports. */
#define GFPIA_OFF_IRQ_TYPE 0x6cU
#define GFPIA_OFF_IRQ_OPERATION 0x70U
#define GFPIA_OFF_IRQ_GROUP 0x80U
#define GFPIA_OFF_IRQ_FINGER 0x84U
#define GFPIA_OFF_IRQ_REMAINING 0x88U
#define GFPIA_OFF_IRQ_RESULT 0x94U
#define GFPIA_OFF_IRQ_STATE 0x98U
#define GFPIA_OFF_IRQ_MODE 0xa8U
#define GFPIA_OFF_IRQ_IMAGE 0x2c5U
#define GFPIA_OFF_IRQ_DUMP 0xd130U

/* What it wants written in before it will answer. */
#define GFPIA_IRQ_STATE_START UINT32_C(1)
#define GFPIA_IRQ_MODE_VALUE UINT32_C(0x200)
#define GFPIA_IRQ_IMAGE_VALUE UINT32_C(0x2000000)

/*
 * One interrupt is not one command. While the state comes back as any of
 * these the application wants the command again, handed back the buffer it
 * just wrote. Until that conversation ends the interrupt is not acknowledged,
 * and an edge-triggered sensor whose line is still asserted raises no more.
 */
#define GFPIA_IRQ_STATE_EVENT UINT32_C(2)
#define GFPIA_IRQ_STATE_AGAIN_FIRST UINT32_C(4)
#define GFPIA_IRQ_STATE_AGAIN_SECOND UINT32_C(5)
#define GFPIA_IRQ_STATE_FRAME UINT32_C(8)
/* Before the frame round the stock driver clears the frame region. */
#define GFPIA_OFF_IRQ_FRAME 0x2f4U
#define GFPIA_IRQ_FRAME_SIZE 0x5a20U
#define GFPIA_IRQ_MAX_ROUNDS 32U

/* Interrupt bits, out of the many the sensor can raise. */
#define GFPIA_IRQ_FINGER_DOWN (UINT32_C(1) << 1)
#define GFPIA_IRQ_FINGER_UP (UINT32_C(1) << 2)
#define GFPIA_IRQ_IMAGE (UINT32_C(1) << 7)

/* Which operation an image was fed to. */
#define GFPIA_OPERATION_ENROL UINT32_C(0)
#define GFPIA_OPERATION_AUTHENTICATE_IMAGE UINT32_C(1)
#define GFPIA_OPERATION_AUTHENTICATE_FF UINT32_C(2)

/* The application's own codes, for the ones worth telling apart. */
#define GFPIA_ERROR_NOT_MATCH UINT32_C(1006)
#define GFPIA_ERROR_ACQUIRED_PARTIAL UINT32_C(1011)
#define GFPIA_ERROR_DUPLICATE_AREA UINT32_C(1045)
#define GFPIA_ERROR_MATCH_FAIL_AND_RETRY UINT32_C(1064)
#define GFPIA_ERROR_ALGO_FAKE UINT32_C(1121)

/* Command 1000 answers with the sensor's configuration; ours starts 0x31. */
#define GFPIA_OFF_CONFIG 0x70U
#define GFPIA_PIANO_CHIP UINT8_C(0x31)

/* Command 1001 wants the byte the driver reports back in its own payload. */
#define GFPIA_OFF_FW_INFO 0x6cU
#define GFPIA_OFF_CHIP_INFO 0x88U

struct gfpia {
	int tee_fd;
	int fp_fd;
	struct qtee_object client_env;
	struct qtee_object loader;
	struct qtee_object controller;
	struct qtee_shared_memory irq_payload;
	uint32_t token;
};

/* One initialisation command, read from the firmware directory. */
struct gfpia_init_step {
	const char *stem;
	uint32_t command;
};

/*
 * The order the stock stack uses, and the only order that works: probe the
 * sensor, tell the application what the driver reported, feed both algorithm
 * models in three pieces each, then finish.
 */
static const struct gfpia_init_step gfpia_init_steps[] = {
	{ "1000", GFPIA_CMD_DETECT_SENSOR },
	{ "1001", GFPIA_CMD_INIT },
	{ "1113-asp-0", GFPIA_CMD_TRANSPORT_DATA },
	{ "1113-asp-1", GFPIA_CMD_TRANSPORT_DATA },
	{ "1113-asp-2", GFPIA_CMD_TRANSPORT_DATA },
	{ "1113-palm-0", GFPIA_CMD_TRANSPORT_DATA },
	{ "1113-palm-1", GFPIA_CMD_TRANSPORT_DATA },
	{ "1113-palm-2", GFPIA_CMD_TRANSPORT_DATA },
	{ "1005", GFPIA_CMD_INIT_FINISHED },
	{ "1014", GFPIA_CMD_SET_ACTIVE_GROUP },
};

#define GFPIA_INIT_STEP_1000 0U
#define GFPIA_INIT_STEP_1001 1U

const char *gfpia_strerror(uint32_t code)
{
	switch (code) {
	case 0:
		return "success";
	case GFPIA_ERROR_NOT_MATCH:
		return "no match";
	case GFPIA_ERROR_ACQUIRED_PARTIAL:
		return "only part of the finger was on the sensor";
	case GFPIA_ERROR_DUPLICATE_AREA:
		return "that part of the finger is already covered";
	case GFPIA_ERROR_MATCH_FAIL_AND_RETRY:
		return "no match, try again";
	case GFPIA_ERROR_ALGO_FAKE:
		return "the anti-spoofing model refused the image";
	default:
		return "unrecognised application error";
	}
}

/*
 * The request carries the local time of day. Every reader of these, the
 * application included, expects milliseconds since local midnight.
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
 * gfpia_build_request() - Fill in one request.
 * @request: %GFPIA_REQUEST_SIZE bytes to write.
 * @token: request token; the stock client counts one per request.
 * @command: which command.
 * @payload_size: the command's own payload length.
 *
 * The declared length is the command's own, never the length of the mapping
 * the payload lives in: a shared-memory allocation is rounded up to a page,
 * and a request declaring more than the command has is refused before the
 * application looks at the payload at all.
 */
static void gfpia_build_request(uint8_t *request, uint32_t token,
				uint32_t command, uint32_t payload_size)
{
	memset(request, 0, GFPIA_REQUEST_SIZE);
	/* Bytes 0..7 stay zero; QTEE patches the payload's address in. */
	write_le32(request + 0x08, token);
	write_le32(request + 0x0c, GFPIA_CLASS_NORMAL);
	write_le64(request + 0x10, milliseconds_since_local_midnight());
	write_le32(request + 0x20, command);
	write_le32(request + 0x24, payload_size);
}

/**
 * gfpia_send() - Send one command and check what came back.
 * @gfpia: handle.
 * @command: which command.
 * @payload: shared memory holding the command's payload.
 * @payload_size: the command's own payload length.
 * @status: where to leave the application's status, or %NULL to insist on zero.
 *
 * Return: Zero on success, a negative errno on failure.
 */
static int gfpia_send(struct gfpia *gfpia, uint32_t command,
		      struct qtee_shared_memory *payload, uint32_t payload_size,
		      uint32_t *status)
{
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t auxiliary;
	uint32_t reported;
	int ret;

	gfpia_build_request(request_data, gfpia->token++, command,
			    payload_size);

	ret = send_request(gfpia->tee_fd, gfpia->controller, &request, payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		return ret;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		secure_free_blob(&response);
		secure_free_blob(&request_output);
		return -EPROTO;
	}

	reported = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	secure_free_blob(&response);
	secure_free_blob(&request_output);

	/*
	 * The auxiliary word is the transport's, not the application's. It is
	 * cleared before the call, so anything in it means the request never
	 * reached the command.
	 */
	if (auxiliary) {
		fprintf(stderr,
			"gfpia: command %" PRIu32 " was refused: 0x%08" PRIx32
			"\n", command, auxiliary);
		return -EPROTO;
	}

	if (status) {
		*status = reported;
		return 0;
	}
	if (reported) {
		fprintf(stderr, "gfpia: command %" PRIu32 " failed: %s (%"
			PRIu32 ")\n", command, gfpia_strerror(reported),
			reported);
		return -EREMOTEIO;
	}

	return 0;
}

/**
 * gfpia_send_simple() - Send a command whose payload is nothing but zeroes.
 * @gfpia: handle.
 * @command: which command.
 * @size: the command's payload length.
 *
 * Return: Zero on success, a negative errno on failure.
 */
static int gfpia_send_simple(struct gfpia *gfpia, uint32_t command,
			     uint32_t size)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	int ret;

	ret = shared_memory_alloc(gfpia->tee_fd, size, &payload);
	if (ret)
		return ret;
	if (payload.size < size) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, size);
	ret = gfpia_send(gfpia, command, &payload, size, NULL);
	secure_shared_memory_release(&payload);

	return ret;
}

/* Where an initialisation step's request and payload live. */
static int gfpia_step_path(char *path, size_t size, const char *directory,
			   const char *prefix, const char *stem)
{
	int length = snprintf(path, size, "%s/%s-%s.bin", directory, prefix,
			      stem);

	if (length < 0 || (size_t)length >= size)
		return -ENAMETOOLONG;
	return 0;
}

/**
 * gfpia_run_init_step() - Send one initialisation command from firmware.
 * @gfpia: handle.
 * @directory: firmware directory.
 * @step: which step.
 * @fw_info: byte to write at %GFPIA_OFF_FW_INFO before sending, for the one
 *           step that wants it; ignored when @patch_fw_info is false.
 * @patch_fw_info: whether @fw_info applies.
 * @payload: where to leave the payload, so the caller can read what came back.
 *
 * The request and payload are shipped rather than built: they carry the
 * sensor configuration and the two algorithm models, which are Goodix's and
 * not something this code could reconstruct.
 *
 * Return: Zero on success, a negative errno on failure.
 */
static int gfpia_run_init_step(struct gfpia *gfpia, const char *directory,
			       const struct gfpia_init_step *step,
			       uint8_t fw_info, bool patch_fw_info,
			       struct qtee_shared_memory *payload)
{
	char path[PATH_MAX];
	struct blob file = { NULL, 0 };
	uint8_t request_data[GFPIA_REQUEST_SIZE];
	struct blob request = { request_data, sizeof(request_data) };
	struct blob request_output = { NULL, 0 };
	struct blob response = { NULL, 0 };
	uint32_t auxiliary;
	uint32_t status;
	int ret;

	ret = gfpia_step_path(path, sizeof(path), directory, "payload",
			      step->stem);
	if (ret)
		return ret;
	ret = read_file(path, MAX_INLINE_IMAGE_SIZE, &file);
	if (ret)
		return ret;

	ret = shared_memory_alloc(gfpia->tee_fd, file.size, payload);
	if (ret) {
		secure_free_blob(&file);
		return ret;
	}
	memset(payload->data, 0, payload->size);
	memcpy(payload->data, file.data, file.size);
	/*
	 * Command 1001 carries the byte the driver reported, and the only copy
	 * the application sees is this one, so it is patched here rather than
	 * in the shipped file.
	 */
	if (patch_fw_info)
		payload->data[GFPIA_OFF_FW_INFO] = fw_info;

	gfpia_build_request(request_data, gfpia->token++, step->command,
			    (uint32_t)file.size);
	ret = send_request(gfpia->tee_fd, gfpia->controller, &request, payload,
			   GFPIA_RESPONSE_SIZE, &request_output, &response);
	if (ret)
		goto out;
	if (response.size != GFPIA_RESPONSE_SIZE) {
		ret = -EPROTO;
		goto out;
	}

	status = read_le32(response.data);
	auxiliary = read_le32(response.data + sizeof(uint32_t));
	if (auxiliary || status) {
		fprintf(stderr,
			"gfpia: initialisation step %s failed: %s (%" PRIu32
			"/0x%08" PRIx32 ")\n", step->stem,
			gfpia_strerror(status), status, auxiliary);
		ret = -EREMOTEIO;
	}

out:
	secure_free_blob(&response);
	secure_free_blob(&request_output);
	secure_free_blob(&file);
	if (ret)
		secure_shared_memory_release(payload);

	return ret;
}

/**
 * gfpia_initialise() - Walk the whole initialisation sequence.
 * @gfpia: handle.
 * @directory: firmware directory.
 *
 * Return: Zero on success, a negative errno on failure.
 */
static int gfpia_initialise(struct gfpia *gfpia, const char *directory)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	uint8_t fw_info = 0;
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(gfpia_init_steps); i++) {
		bool patch = i == GFPIA_INIT_STEP_1001;

		ret = gfpia_run_init_step(gfpia, directory,
					  &gfpia_init_steps[i], fw_info, patch,
					  &payload);
		if (ret)
			return ret;

		if (i == GFPIA_INIT_STEP_1000) {
			if (payload.data[GFPIA_OFF_CONFIG] !=
			    GFPIA_PIANO_CHIP) {
				fprintf(stderr,
					"gfpia: sensor answered with chip 0x%02x, expected 0x%02x\n",
					payload.data[GFPIA_OFF_CONFIG],
					GFPIA_PIANO_CHIP);
				secure_shared_memory_release(&payload);
				return -ENODEV;
			}
		}

		secure_shared_memory_release(&payload);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * open_fingerprint_uio() - Find and open the sensor's UIO device.
 *
 * The minor number is whatever UIO handed out, so the device is identified by
 * the name the driver registered rather than by path.
 *
 * Return: An open descriptor, or a negative errno.
 */
static int open_fingerprint_uio(void)
{
	DIR *dir;
	struct dirent *entry;
	int fd = -ENODEV;

	dir = opendir(XIAOMI_FP_UIO_CLASS);
	if (!dir)
		return report_errno(XIAOMI_FP_UIO_CLASS);

	while ((entry = readdir(dir))) {
		char path[PATH_MAX];
		char name[64];
		FILE *file;
		size_t length;

		if (strncmp(entry->d_name, "uio", 3))
			continue;

		snprintf(path, sizeof(path), "%s/%s/name",
			 XIAOMI_FP_UIO_CLASS, entry->d_name);
		file = fopen(path, "re");
		if (!file)
			continue;
		if (!fgets(name, sizeof(name), file)) {
			fclose(file);
			continue;
		}
		fclose(file);

		length = strcspn(name, "\n");
		name[length] = '\0';
		if (strcmp(name, XIAOMI_FP_UIO_NAME))
			continue;

		snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
		fd = open(path, O_RDWR | O_CLOEXEC);
		if (fd < 0)
			fd = report_errno(path);
		break;
	}

	closedir(dir);

	if (fd == -ENODEV)
		fprintf(stderr, "gfpia: no UIO device named %s; is %s loaded?\n",
			XIAOMI_FP_UIO_NAME, XIAOMI_FP_UIO_NAME);

	return fd;
}

int gfpia_open(const char *firmware_dir, struct gfpia **out)
{
	char tee_path[PATH_MAX];
	struct gfpia *gfpia;
	int ret;

	if (!firmware_dir || !out)
		return -EINVAL;

	gfpia = calloc(1, sizeof(*gfpia));
	if (!gfpia)
		return -ENOMEM;
	gfpia->tee_fd = -1;
	gfpia->fp_fd = -1;
	gfpia->irq_payload.id = -1;
	gfpia->irq_payload.fd = -1;
	gfpia->token = 1;

	/*
	 * Opening it is the whole of bringing the sensor up: the driver's
	 * runtime PM raises the supply, pulses reset and unmasks the interrupt,
	 * and undoes all of it when the last descriptor closes - including when
	 * it closes because this process died.
	 */
	gfpia->fp_fd = open_fingerprint_uio();
	if (gfpia->fp_fd < 0) {
		ret = gfpia->fp_fd;
		gfpia->fp_fd = -1;
		goto fail;
	}

	/* This hands back the descriptor itself, already open. */
	gfpia->tee_fd = find_qcomtee_device(tee_path, sizeof(tee_path));
	if (gfpia->tee_fd < 0) {
		ret = gfpia->tee_fd;
		goto fail;
	}

	ret = get_client_env(gfpia->tee_fd, &gfpia->client_env);
	if (ret)
		goto fail;
	ret = client_env_open(gfpia->tee_fd, gfpia->client_env,
			      QSEECOM_APP_LOADER_UID, &gfpia->loader);
	if (ret)
		goto fail;
	ret = start_app(gfpia->tee_fd, gfpia->loader, GFPIA_APP_NAME,
			firmware_dir, &gfpia->controller);
	if (ret)
		goto fail;

	ret = shared_memory_alloc(gfpia->tee_fd, GFPIA_IRQ_PAYLOAD_SIZE,
				  &gfpia->irq_payload);
	if (ret)
		goto fail;
	if (gfpia->irq_payload.size < GFPIA_IRQ_PAYLOAD_SIZE) {
		ret = -ENOSPC;
		goto fail;
	}

	/* See GFPIA_DETECT_BASE: a kept baseline is worse than none. */
	if (unlink(GFPIA_DETECT_BASE) && errno != ENOENT)
		fprintf(stderr, "gfpia: cannot drop the stale detect base: %s\n",
			strerror(errno));

	ret = gfpia_initialise(gfpia, firmware_dir);
	if (ret)
		goto fail;

	*out = gfpia;
	return 0;

fail:
	gfpia_close(gfpia);
	return ret;
}

void gfpia_close(struct gfpia *gfpia)
{
	if (!gfpia)
		return;

	secure_shared_memory_release(&gfpia->irq_payload);
	if (gfpia->tee_fd >= 0) {
		/*
		 * The application is deliberately left loaded.
		 *
		 * Unloading it is what breaks it: QTEE accepts a load that
		 * follows an unload and then refuses the first command sent to
		 * the new copy, for the rest of the boot. Since fprintd exits
		 * whenever it goes idle, unloading here would mean the sensor
		 * worked once per boot. Dropping only our references costs a
		 * resident application and nothing else - the sensor's rail and
		 * its interrupt are released through the ioctls below.
		 */
		object_release(gfpia->tee_fd, &gfpia->controller);
		object_release(gfpia->tee_fd, &gfpia->loader);
		object_release(gfpia->tee_fd, &gfpia->client_env);
		close(gfpia->tee_fd);
	}
	/* The driver drops the supply and masks the interrupt from here. */
	if (gfpia->fp_fd >= 0)
		close(gfpia->fp_fd);
	free(gfpia);
}

int gfpia_irq_fd(const struct gfpia *gfpia)
{
	return gfpia ? gfpia->fp_fd : -1;
}

int gfpia_list(struct gfpia *gfpia, uint32_t *groups, uint32_t *fingers,
	       size_t max, size_t *count)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	size_t found = 0;
	unsigned int i;
	int ret;

	if (!gfpia || !groups || !fingers || !count)
		return -EINVAL;

	ret = shared_memory_alloc(gfpia->tee_fd, GFPIA_ENUMERATE_PAYLOAD_SIZE,
				  &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_ENUMERATE_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}
	memset(payload.data, 0, GFPIA_ENUMERATE_PAYLOAD_SIZE);

	ret = gfpia_send(gfpia, GFPIA_CMD_ENUMERATE, &payload,
			 GFPIA_ENUMERATE_PAYLOAD_SIZE, NULL);
	if (ret)
		goto out;

	for (i = 0; i < GFPIA_MAX_FINGERS && found < max; i++) {
		uint32_t finger = read_le32(payload.data +
					    GFPIA_OFF_ENUM_FINGER +
					    i * sizeof(uint32_t));

		if (!finger)
			continue;
		groups[found] = read_le32(payload.data + GFPIA_OFF_ENUM_GROUP +
					  i * sizeof(uint32_t));
		fingers[found] = finger;
		found++;
	}
	*count = found;

out:
	secure_shared_memory_release(&payload);

	return ret;
}

/*
 * Android's authentication token: a version byte, then the challenge, user and
 * authenticator identifiers as little-endian 64-bit values, then a big-endian
 * type and timestamp, then an HMAC. On a system with no gatekeeper there is no
 * key to sign with, and this application does not check: only the challenge
 * has to be right.
 */
static void gfpia_build_auth_token(uint8_t *token, uint64_t challenge)
{
	memset(token, 0, GFPIA_AUTH_TOKEN_SIZE);
	token[0] = 0;
	write_le64(token + 1, challenge);
}

int gfpia_enrol_begin(struct gfpia *gfpia, uint32_t group)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	uint64_t challenge;
	int ret;

	if (!gfpia)
		return -EINVAL;

	/*
	 * Pre-enrol clears the application's enrolment count and answers with
	 * the challenge the token has to be built over.
	 */
	ret = shared_memory_alloc(gfpia->tee_fd, GFPIA_PRE_ENROL_PAYLOAD_SIZE,
				  &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_PRE_ENROL_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}
	memset(payload.data, 0, GFPIA_PRE_ENROL_PAYLOAD_SIZE);

	ret = gfpia_send(gfpia, GFPIA_CMD_PRE_ENROL, &payload,
			 GFPIA_PRE_ENROL_PAYLOAD_SIZE, NULL);
	if (ret) {
		secure_shared_memory_release(&payload);
		return ret;
	}
	challenge = read_le64(payload.data + GFPIA_OFF_CHALLENGE);
	secure_shared_memory_release(&payload);
	if (getenv("GFPIA_TRACE"))
		fprintf(stderr, "gfpia: pre-enrol ok, challenge 0x%016" PRIx64
			"\n", challenge);

	ret = shared_memory_alloc(gfpia->tee_fd, GFPIA_ENROL_PAYLOAD_SIZE,
				  &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_ENROL_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, GFPIA_ENROL_PAYLOAD_SIZE);
	write_le32(payload.data + GFPIA_OFF_ENROL_GROUP, group);
	payload.data[GFPIA_OFF_ENROL_DUMP] = 0;
	gfpia_build_auth_token(payload.data + GFPIA_OFF_ENROL_TOKEN,
			       challenge);

	ret = gfpia_send(gfpia, GFPIA_CMD_ENROL, &payload,
			 GFPIA_ENROL_PAYLOAD_SIZE, NULL);
	secure_shared_memory_release(&payload);
	if (getenv("GFPIA_TRACE"))
		fprintf(stderr, "gfpia: enrol returned %d\n", ret);

	return ret;
}

int gfpia_enrol_finish(struct gfpia *gfpia, uint32_t group, uint32_t finger)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	int ret;

	if (!gfpia || !finger)
		return -EINVAL;

	ret = gfpia_send_simple(gfpia, GFPIA_CMD_POST_ENROL,
				GFPIA_COMMON_PAYLOAD_SIZE);
	if (ret)
		return ret;

	ret = shared_memory_alloc(gfpia->tee_fd, GFPIA_SAVE_PAYLOAD_SIZE,
				  &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_SAVE_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, GFPIA_SAVE_PAYLOAD_SIZE);
	write_le32(payload.data + GFPIA_OFF_SAVE_GROUP, group);
	write_le32(payload.data + GFPIA_OFF_SAVE_FINGER, finger);

	ret = gfpia_send(gfpia, GFPIA_CMD_SAVE, &payload,
			 GFPIA_SAVE_PAYLOAD_SIZE, NULL);
	secure_shared_memory_release(&payload);

	return ret;
}

int gfpia_verify_begin(struct gfpia *gfpia, uint32_t group)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	int ret;

	if (!gfpia)
		return -EINVAL;

	ret = shared_memory_alloc(gfpia->tee_fd,
				  GFPIA_AUTHENTICATE_PAYLOAD_SIZE, &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_AUTHENTICATE_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, GFPIA_AUTHENTICATE_PAYLOAD_SIZE);
	write_le32(payload.data + GFPIA_OFF_AUTH_GROUP, group);
	write_le64(payload.data + GFPIA_OFF_AUTH_OPERATION, 0);
	write_le32(payload.data + GFPIA_OFF_AUTH_SENTINEL, UINT32_MAX);

	ret = gfpia_send(gfpia, GFPIA_CMD_AUTHENTICATE, &payload,
			 GFPIA_AUTHENTICATE_PAYLOAD_SIZE, NULL);
	secure_shared_memory_release(&payload);
	if (getenv("GFPIA_TRACE"))
		fprintf(stderr, "gfpia: authenticate returned %d\n", ret);

	return ret;
}

int gfpia_cancel(struct gfpia *gfpia)
{
	if (!gfpia)
		return -EINVAL;

	return gfpia_send_simple(gfpia, GFPIA_CMD_CANCEL,
				 GFPIA_COMMON_PAYLOAD_SIZE);
}

int gfpia_delete(struct gfpia *gfpia, uint32_t group, uint32_t finger)
{
	struct qtee_shared_memory payload = { .id = -1, .fd = -1 };
	int ret;

	if (!gfpia || !finger)
		return -EINVAL;

	ret = shared_memory_alloc(gfpia->tee_fd, GFPIA_REMOVE_PAYLOAD_SIZE,
				  &payload);
	if (ret)
		return ret;
	if (payload.size < GFPIA_REMOVE_PAYLOAD_SIZE) {
		shared_memory_release(&payload);
		return -ENOSPC;
	}

	memset(payload.data, 0, GFPIA_REMOVE_PAYLOAD_SIZE);
	write_le32(payload.data + GFPIA_OFF_SAVE_GROUP, group);
	write_le32(payload.data + GFPIA_OFF_SAVE_FINGER, finger);

	ret = gfpia_send(gfpia, GFPIA_CMD_REMOVE, &payload,
			 GFPIA_REMOVE_PAYLOAD_SIZE, NULL);
	secure_shared_memory_release(&payload);

	return ret;
}

/* The four fields the stock driver writes before each first round. */
static void gfpia_irq_prepare(struct qtee_shared_memory *payload)
{
	memset(payload->data, 0, GFPIA_IRQ_PAYLOAD_SIZE);
	write_le32(payload->data + GFPIA_OFF_IRQ_STATE, GFPIA_IRQ_STATE_START);
	write_le32(payload->data + GFPIA_OFF_IRQ_MODE, GFPIA_IRQ_MODE_VALUE);
	write_le32(payload->data + GFPIA_OFF_IRQ_IMAGE, GFPIA_IRQ_IMAGE_VALUE);
	payload->data[GFPIA_OFF_IRQ_DUMP] = 0;
}

static bool gfpia_irq_state_wants_more(uint32_t state)
{
	return state == GFPIA_IRQ_STATE_EVENT ||
	       state == GFPIA_IRQ_STATE_AGAIN_FIRST ||
	       state == GFPIA_IRQ_STATE_AGAIN_SECOND ||
	       state == GFPIA_IRQ_STATE_FRAME;
}

/* Turn one answered round into something a caller can act on. */
static void gfpia_classify(const uint8_t *payload, uint32_t status,
			   struct gfpia_event *event)
{
	uint32_t type = read_le32(payload + GFPIA_OFF_IRQ_TYPE);
	uint32_t operation = read_le32(payload + GFPIA_OFF_IRQ_OPERATION);
	uint32_t finger = read_le32(payload + GFPIA_OFF_IRQ_FINGER);

	if (!(type & GFPIA_IRQ_IMAGE)) {
		if (type & GFPIA_IRQ_FINGER_DOWN)
			event->kind = GFPIA_EVENT_FINGER_DOWN;
		else if (type & GFPIA_IRQ_FINGER_UP)
			event->kind = GFPIA_EVENT_FINGER_UP;
		return;
	}

	event->group = read_le32(payload + GFPIA_OFF_IRQ_GROUP);
	event->finger = finger;
	event->remaining = read_le16(payload + GFPIA_OFF_IRQ_REMAINING);
	event->error = status;

	if (operation == GFPIA_OPERATION_ENROL) {
		if (status)
			event->kind = GFPIA_EVENT_RETRY;
		else if (event->remaining)
			event->kind = GFPIA_EVENT_ENROL_PROGRESS;
		else
			event->kind = GFPIA_EVENT_ENROL_DONE;
		return;
	}

	if (operation == GFPIA_OPERATION_AUTHENTICATE_IMAGE ||
	    operation == GFPIA_OPERATION_AUTHENTICATE_FF) {
		if (!status && finger)
			event->kind = GFPIA_EVENT_MATCH;
		else if (status == GFPIA_ERROR_ACQUIRED_PARTIAL ||
			 status == GFPIA_ERROR_ALGO_FAKE)
			event->kind = GFPIA_EVENT_RETRY;
		else
			event->kind = GFPIA_EVENT_NO_MATCH;
		return;
	}

	/* Some other operation's image; nothing here can act on it. */
	if (status)
		event->kind = GFPIA_EVENT_RETRY;
}

int gfpia_handle_irq(struct gfpia *gfpia, struct gfpia_event *event)
{
	struct gfpia_event best = { .kind = GFPIA_EVENT_NONE };
	unsigned int round;
	uint32_t events;
	int ret;

	if (!gfpia || !event)
		return -EINVAL;

	/* UIO reads are the event counter and refuse any other length. */
	if (read(gfpia->fp_fd, &events, sizeof(events)) != (ssize_t)sizeof(events))
		return report_errno("fingerprint interrupt");

	gfpia_irq_prepare(&gfpia->irq_payload);
	for (round = 0; round < GFPIA_IRQ_MAX_ROUNDS; round++) {
		struct gfpia_event current = { .kind = GFPIA_EVENT_NONE };
		uint32_t status = 0;
		uint32_t state;

		ret = gfpia_send(gfpia, GFPIA_CMD_IRQ, &gfpia->irq_payload,
				 GFPIA_IRQ_PAYLOAD_SIZE, &status);
		if (ret)
			return ret;

		state = read_le32(gfpia->irq_payload.data + GFPIA_OFF_IRQ_STATE);
		if (getenv("GFPIA_TRACE"))
			fprintf(stderr,
				"gfpia: round %u type 0x%08" PRIx32 " operation %"
				PRIu32 " remaining %u status %" PRIu32
				" state %" PRIu32 "\n", round,
				read_le32(gfpia->irq_payload.data +
					  GFPIA_OFF_IRQ_TYPE),
				read_le32(gfpia->irq_payload.data +
					  GFPIA_OFF_IRQ_OPERATION),
				read_le16(gfpia->irq_payload.data +
					  GFPIA_OFF_IRQ_REMAINING),
				status, state);

		gfpia_classify(gfpia->irq_payload.data, status, &current);
		/*
		 * An image is the interesting round; a finger arriving or
		 * leaving only matters if nothing better follows.
		 */
		if (current.kind != GFPIA_EVENT_NONE &&
		    (best.kind == GFPIA_EVENT_NONE ||
		     best.kind == GFPIA_EVENT_FINGER_DOWN ||
		     best.kind == GFPIA_EVENT_FINGER_UP))
			best = current;

		if (!gfpia_irq_state_wants_more(state))
			break;
		if (state == GFPIA_IRQ_STATE_FRAME)
			memset(gfpia->irq_payload.data + GFPIA_OFF_IRQ_FRAME, 0,
			       GFPIA_IRQ_FRAME_SIZE);
	}

	*event = best;

	return 0;
}
