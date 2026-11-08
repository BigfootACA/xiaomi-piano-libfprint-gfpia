// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Exercise the gfpia layer on its own, before any of it is asked to live
 * inside libfprint's main loop.
 *
 *   gfpia-test FIRMWARE_DIR list
 *   gfpia-test FIRMWARE_DIR enrol   [SECONDS]
 *   gfpia-test FIRMWARE_DIR verify  [SECONDS]
 *   gfpia-test FIRMWARE_DIR delete  FINGER
 *   gfpia-test FIRMWARE_DIR switch  [SECONDS]

 * "switch" is the awkward case: match once, end that operation, then enrol.
 * A sensor that is never re-armed for the second operation shows up here in
 * two presses instead of forty.
 *
 * The point is the poll loop: nothing here blocks on the sensor, which is the
 * property a driver in someone else's main loop needs.
 */

#include "gfpia.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_SECONDS 300

static void print_fingers(struct gfpia *gfpia, const char *label)
{
	uint32_t groups[GFPIA_MAX_FINGERS];
	uint32_t fingers[GFPIA_MAX_FINGERS];
	size_t count = 0;
	size_t i;
	int ret;

	ret = gfpia_list(gfpia, groups, fingers, GFPIA_MAX_FINGERS, &count);
	if (ret) {
		fprintf(stderr, "%s: cannot list fingers: %s\n", label,
			strerror(-ret));
		return;
	}

	printf("%s: %zu finger(s)\n", label, count);
	for (i = 0; i < count; i++)
		printf("  group %" PRIu32 ", finger %" PRIu32 "\n", groups[i],
		       fingers[i]);
}

/**
 * wait_for_event() - Poll until the sensor says something.
 * @gfpia: handle.
 * @deadline: when to give up.
 * @event: where to leave what it said.
 *
 * Return: 1 when @event was filled in, 0 on timeout, < 0 on failure.
 */
static int wait_for_event(struct gfpia *gfpia, time_t deadline,
			  struct gfpia_event *event)
{
	for (;;) {
		struct pollfd fds = {
			.fd = gfpia_irq_fd(gfpia),
			.events = POLLIN,
		};
		time_t now = time(NULL);
		int ready;
		int ret;

		if (now >= deadline)
			return 0;

		ready = poll(&fds, 1, (int)(deadline - now) * 1000);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			return -errno;
		}
		if (!ready)
			return 0;

		ret = gfpia_handle_irq(gfpia, event);
		if (ret)
			return ret;
		if (event->kind != GFPIA_EVENT_NONE)
			return 1;
	}
}

/**
 * run_switch() - Match once, end it, then start enrolling.
 * @gfpia: handle.
 * @seconds: how long to wait for each press.
 *
 * The question this answers is whether an operation that follows another one
 * ever sees a finger.
 *
 * Return: Zero when the second operation saw a press, < 0 otherwise.
 */
static int run_switch(struct gfpia *gfpia, unsigned int seconds)
{
	struct gfpia_event event = { .kind = GFPIA_EVENT_NONE };
	time_t deadline;
	int ret;

	ret = gfpia_verify_begin(gfpia, 0);
	if (ret) {
		fprintf(stderr, "cannot start matching: %s\n", strerror(-ret));
		return ret;
	}
	printf("first: touch the sensor once\n");
	fflush(stdout);

	deadline = time(NULL) + (time_t)seconds;
	for (;;) {
		ret = wait_for_event(gfpia, deadline, &event);
		if (ret < 0)
			return ret;
		if (!ret) {
			fprintf(stderr, "no press arrived for the match\n");
			return -ETIMEDOUT;
		}
		if (event.kind == GFPIA_EVENT_MATCH ||
		    event.kind == GFPIA_EVENT_NO_MATCH)
			break;
		printf("  (%d)\n", event.kind);
		fflush(stdout);
	}
	printf("match finished: kind %d, finger %" PRIu32 "\n", event.kind,
	       event.finger);

	ret = gfpia_cancel(gfpia);
	printf("cancel returned %d\n", ret);

	ret = gfpia_enrol_begin(gfpia, 0);
	if (ret) {
		fprintf(stderr, "cannot start enrolling: %s\n", strerror(-ret));
		return ret;
	}
	printf("second: touch the sensor again\n");
	fflush(stdout);

	deadline = time(NULL) + (time_t)seconds;
	ret = wait_for_event(gfpia, deadline, &event);
	if (ret < 0)
		return ret;
	if (!ret) {
		printf("RESULT: the sensor was never armed for the enrolment\n");
		return -ETIMEDOUT;
	}

	printf("RESULT: the enrolment saw a press: kind %d, remaining %"
	       PRIu32 "\n", event.kind, event.remaining);

	return 0;
}

static int run_enrol(struct gfpia *gfpia, unsigned int seconds)
{
	time_t deadline = time(NULL) + (time_t)seconds;
	int ret;

	ret = gfpia_enrol_begin(gfpia, 0);
	if (ret) {
		fprintf(stderr, "cannot start enrolling: %s\n", strerror(-ret));
		return ret;
	}
	printf("enrolling; touch the sensor\n");
	fflush(stdout);

	for (;;) {
		struct gfpia_event event = { .kind = GFPIA_EVENT_NONE };

		ret = wait_for_event(gfpia, deadline, &event);
		if (ret < 0)
			return ret;
		if (!ret) {
			fprintf(stderr, "gave up waiting\n");
			return -ETIMEDOUT;
		}

		switch (event.kind) {
		case GFPIA_EVENT_ENROL_PROGRESS:
			printf("%" PRIu32 " more\n", event.remaining);
			break;
		case GFPIA_EVENT_RETRY:
			printf("again: %s\n", gfpia_strerror(event.error));
			break;
		case GFPIA_EVENT_ENROL_DONE:
			printf("enrolled group %" PRIu32 ", finger %" PRIu32
			       "\n", event.group, event.finger);
			ret = gfpia_enrol_finish(gfpia, event.group,
						 event.finger);
			if (ret) {
				fprintf(stderr, "cannot store it: %s\n",
					strerror(-ret));
				return ret;
			}
			printf("stored\n");
			return 0;
		default:
			break;
		}
		fflush(stdout);
	}
}

static int run_verify(struct gfpia *gfpia, unsigned int seconds)
{
	time_t deadline = time(NULL) + (time_t)seconds;
	int ret;

	ret = gfpia_verify_begin(gfpia, 0);
	if (ret) {
		fprintf(stderr, "cannot start matching: %s\n", strerror(-ret));
		return ret;
	}
	printf("matching; touch the sensor\n");
	fflush(stdout);

	for (;;) {
		struct gfpia_event event = { .kind = GFPIA_EVENT_NONE };

		ret = wait_for_event(gfpia, deadline, &event);
		if (ret < 0)
			return ret;
		if (!ret) {
			fprintf(stderr, "gave up waiting\n");
			return -ETIMEDOUT;
		}

		switch (event.kind) {
		case GFPIA_EVENT_MATCH:
			printf("matched finger %" PRIu32 " in group %" PRIu32
			       "\n", event.finger, event.group);
			return 0;
		case GFPIA_EVENT_NO_MATCH:
			printf("no match: %s\n", gfpia_strerror(event.error));
			return 0;
		case GFPIA_EVENT_RETRY:
			printf("again: %s\n", gfpia_strerror(event.error));
			break;
		default:
			break;
		}
		fflush(stdout);
	}
}

int main(int argc, char **argv)
{
	unsigned int seconds = DEFAULT_SECONDS;
	struct gfpia *gfpia = NULL;
	const char *directory;
	const char *action;
	int ret;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s FIRMWARE_DIR list|enrol|verify|switch|delete [ARG]\n",
			argv[0]);
		return EXIT_FAILURE;
	}
	directory = argv[1];
	action = argv[2];

	if (argc > 3 && strcmp(action, "delete")) {
		char *end = NULL;
		unsigned long value = strtoul(argv[3], &end, 10);

		if (!end || *end || !value || value > 3600) {
			fprintf(stderr, "SECONDS must be 1..3600\n");
			return EXIT_FAILURE;
		}
		seconds = (unsigned int)value;
	}

	ret = gfpia_open(directory, &gfpia);
	if (ret) {
		fprintf(stderr, "cannot open the sensor: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}
	printf("sensor ready\n");

	if (!strcmp(action, "list")) {
		print_fingers(gfpia, "stored");
		ret = 0;
	} else if (!strcmp(action, "enrol")) {
		print_fingers(gfpia, "before");
		ret = run_enrol(gfpia, seconds);
		if (!ret)
			print_fingers(gfpia, "after");
	} else if (!strcmp(action, "switch")) {
		ret = run_switch(gfpia, seconds);
	} else if (!strcmp(action, "verify")) {
		print_fingers(gfpia, "stored");
		ret = run_verify(gfpia, seconds);
	} else if (!strcmp(action, "delete")) {
		char *end = NULL;
		unsigned long finger;

		if (argc != 4) {
			fprintf(stderr, "delete needs a finger\n");
			ret = -EINVAL;
			goto out;
		}
		finger = strtoul(argv[3], &end, 10);
		if (!end || *end || !finger || finger > UINT32_MAX) {
			fprintf(stderr, "FINGER is not a finger\n");
			ret = -EINVAL;
			goto out;
		}
		ret = gfpia_delete(gfpia, 0, (uint32_t)finger);
		if (!ret)
			print_fingers(gfpia, "after");
	} else {
		fprintf(stderr, "unknown action %s\n", action);
		ret = -EINVAL;
	}

out:
	gfpia_close(gfpia);

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
