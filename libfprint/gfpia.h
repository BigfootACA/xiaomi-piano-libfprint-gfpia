/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The Goodix gfpia fingerprint application, as it is spoken on a Xiaomi
 * Pad 8 Pro.
 *
 * The sensor is match-on-chip: images never leave the secure world, and this
 * side only ever starts an operation and then reads what the application says
 * about each interrupt. Nothing here blocks waiting for a finger. Poll the
 * descriptor gfpia_irq_fd() returns and call gfpia_handle_irq() when it is
 * readable, which is what lets a driver live inside someone else's main loop.
 *
 * The protocol itself is written down in
 * qcomtee/goodix-gfpia.md.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Ten is as many fingers as the application will hold. */
#define GFPIA_MAX_FINGERS 10U

/**
 * enum gfpia_event_kind - What one interrupt turned out to mean.
 * @GFPIA_EVENT_NONE: nothing worth acting on.
 * @GFPIA_EVENT_FINGER_DOWN: a finger arrived.
 * @GFPIA_EVENT_FINGER_UP: it left again.
 * @GFPIA_EVENT_RETRY: an image was taken and refused; press again.
 * @GFPIA_EVENT_ENROL_PROGRESS: an image was kept and more are wanted.
 * @GFPIA_EVENT_ENROL_DONE: the last image was kept.
 * @GFPIA_EVENT_MATCH: a stored finger was recognised.
 * @GFPIA_EVENT_NO_MATCH: none was.
 */
enum gfpia_event_kind {
	GFPIA_EVENT_NONE,
	GFPIA_EVENT_FINGER_DOWN,
	GFPIA_EVENT_FINGER_UP,
	GFPIA_EVENT_RETRY,
	GFPIA_EVENT_ENROL_PROGRESS,
	GFPIA_EVENT_ENROL_DONE,
	GFPIA_EVENT_MATCH,
	GFPIA_EVENT_NO_MATCH,
};

/**
 * struct gfpia_event - What the application reported about one interrupt.
 * @kind: which of the above it was.
 * @error: the application's own code, for %GFPIA_EVENT_RETRY.
 * @remaining: images still wanted, while enrolling.
 * @group: the group a finger belongs to.
 * @finger: the finger the application named, enrolling or matching.
 */
struct gfpia_event {
	enum gfpia_event_kind kind;
	uint32_t error;
	uint32_t remaining;
	uint32_t group;
	uint32_t finger;
};

struct gfpia;

/**
 * gfpia_open() - Power the sensor, load the application and initialise it.
 * @firmware_dir: directory holding the application's split image and the
 *                initialisation requests and payloads.
 * @out: where to leave the handle.
 *
 * Everything the sensor needs before it will report a finger happens here:
 * the rails come up, the application is loaded, its sensor configuration and
 * both algorithm models go in, and the active group is selected.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_open(const char *firmware_dir, struct gfpia **out);

/**
 * gfpia_close() - Undo gfpia_open().
 * @gfpia: handle, which may be %NULL.
 */
void gfpia_close(struct gfpia *gfpia);

/**
 * gfpia_irq_fd() - The descriptor that becomes readable on a sensor interrupt.
 * @gfpia: handle.
 *
 * Return: A descriptor to poll. It is owned by @gfpia.
 */
int gfpia_irq_fd(const struct gfpia *gfpia);

/**
 * gfpia_handle_irq() - Consume one interrupt and say what it meant.
 * @gfpia: handle.
 * @event: where to leave the answer.
 *
 * Call this once the descriptor is readable. One interrupt can take several
 * exchanges with the application; this does all of them before returning.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_handle_irq(struct gfpia *gfpia, struct gfpia_event *event);

/**
 * gfpia_list() - Ask which fingers the application holds.
 * @gfpia: handle.
 * @groups: where to write each finger's group.
 * @fingers: where to write each finger.
 * @max: how many @groups and @fingers can hold.
 * @count: where to leave how many were written.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_list(struct gfpia *gfpia, uint32_t *groups, uint32_t *fingers,
	       size_t max, size_t *count);

/**
 * gfpia_enrol_begin() - Start building a new finger.
 * @gfpia: handle.
 * @group: group to enrol into.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_enrol_begin(struct gfpia *gfpia, uint32_t group);

/**
 * gfpia_enrol_finish() - Store the finger that was just built.
 * @gfpia: handle.
 * @group: the group the application named.
 * @finger: the finger the application named.
 *
 * Call this after %GFPIA_EVENT_ENROL_DONE, with the identifiers that event
 * carried: the application chooses them, not the caller.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_enrol_finish(struct gfpia *gfpia, uint32_t group, uint32_t finger);

/**
 * gfpia_verify_begin() - Ask for the next finger to be matched.
 * @gfpia: handle.
 * @group: group to match against.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_verify_begin(struct gfpia *gfpia, uint32_t group);

/**
 * gfpia_cancel() - Abandon whatever operation is running.
 * @gfpia: handle.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_cancel(struct gfpia *gfpia);

/**
 * gfpia_delete() - Forget one stored finger.
 * @gfpia: handle.
 * @group: its group.
 * @finger: the finger.
 *
 * Return: Zero on success, a negative errno on failure.
 */
int gfpia_delete(struct gfpia *gfpia, uint32_t group, uint32_t finger);

/**
 * gfpia_strerror() - Name one of the application's own error codes.
 * @code: the code.
 *
 * Return: A static string; never %NULL.
 */
const char *gfpia_strerror(uint32_t code);
