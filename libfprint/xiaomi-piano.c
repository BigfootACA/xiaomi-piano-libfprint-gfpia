// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The side fingerprint sensor of a Xiaomi Pad 8 Pro.
 *
 * The sensor is a Goodix reader driven entirely from the secure world: images
 * never reach this side, and neither do templates. Everything here does is
 * start an operation, wait for the interrupt the kernel shim reports, and ask
 * the trusted application what it made of the finger. That makes this a
 * match-on-chip driver with device storage, and the identity of a print is the
 * identifier the application chose for it.
 *
 * The protocol lives in gfpia.c, and where it came from is written down in
 * qcomtee/goodix-gfpia.md.
 */

#define FP_COMPONENT "xiaomi_piano"

#include "drivers_api.h"
#include "gfpia.h"

#include <glib-unix.h>

/*
 * Where the application's image and its initialisation payloads live. The
 * sensor configuration and both algorithm models are Goodix's, so they are
 * shipped rather than built.
 */
#define XIAOMI_PIANO_FIRMWARE_DIR \
  "/lib/firmware/qcom/sm8750/xiaomi/piano-fp"

/* The application counts down from this many usable images. */
#define XIAOMI_PIANO_ENROLL_STAGES 25

/* The one group this driver uses; the stock stack calls it the main user. */
#define XIAOMI_PIANO_GROUP 0

struct _FpiDeviceXiaomiPiano
{
  FpDevice   parent;

  struct gfpia *gfpia;
  guint         irq_source;

  /* How many images the application has kept, for enrolment progress. */
  guint         stages_done;
};

G_DECLARE_FINAL_TYPE (FpiDeviceXiaomiPiano, fpi_device_xiaomi_piano, FPI,
                      DEVICE_XIAOMI_PIANO, FpDevice)
G_DEFINE_TYPE (FpiDeviceXiaomiPiano, fpi_device_xiaomi_piano, FP_TYPE_DEVICE)

/*
 * A print is identified by the number the application gave it. Nothing else
 * survives on the device, so the user id is derived from that number rather
 * than stored alongside it.
 */
static gchar *
user_id_for_finger (guint32 finger)
{
  return g_strdup_printf ("FP-XIAOMI-PIANO-%08X", finger);
}

static FpPrint *
print_for_finger (FpDevice *device, guint32 finger)
{
  g_autofree gchar *user_id = user_id_for_finger (finger);
  FpPrint *print = fp_print_new (device);

  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  fpi_print_fill_from_user_id (print, user_id);
  g_object_set (print, "fpi-data", g_variant_new_uint32 (finger), NULL);

  return print;
}

/**
 * finger_for_print() - Recover the application's identifier from a print.
 * @print: the print.
 * @finger: where to leave the identifier.
 *
 * Returns: %TRUE when @print came from this driver and carries one.
 */
static gboolean
finger_for_print (FpPrint *print, guint32 *finger)
{
  g_autoptr(GVariant) data = NULL;

  if (!print || !fp_print_get_device_stored (print))
    return FALSE;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE_UINT32))
    return FALSE;

  *finger = g_variant_get_uint32 (data);

  return *finger != 0;
}

/* Turn one of the application's complaints into something a user can act on. */
static FpDeviceRetry
retry_reason (guint32 error)
{
  switch (error)
    {
    case 1011:                 /* only part of the finger was on the sensor */
    case 1045:                 /* that part is already covered */
      return FP_DEVICE_RETRY_CENTER_FINGER;

    default:
      return FP_DEVICE_RETRY_GENERAL;
    }
}

static void stop_listening (FpiDeviceXiaomiPiano *self);

/*
 * One interrupt, dispatched to whatever the device was asked to do. Returning
 * %G_SOURCE_CONTINUE keeps the watch; every path that finishes an operation
 * drops it first.
 */
/*
 * Tell the application an operation is over.
 *
 * Completing an action is this side's bookkeeping; the application knows
 * nothing about it and goes on believing the matching or enrolment it was
 * asked for is still running. The next operation is then accepted but the
 * sensor is never armed for it, and no finger is ever seen again. Cancelling
 * has to happen here, once something has actually run - sending it into an
 * idle application instead simply disarms the sensor.
 */
static void
finish_operation (FpiDeviceXiaomiPiano *self)
{
  int ret = gfpia_cancel (self->gfpia);

  if (ret)
    fp_dbg ("cannot end the operation cleanly: %s", g_strerror (-ret));
}

static gboolean
on_sensor_interrupt (gint fd, GIOCondition condition, gpointer user_data)
{
  FpiDeviceXiaomiPiano *self = user_data;
  FpDevice *device = FP_DEVICE (self);
  struct gfpia_event event = { .kind = GFPIA_EVENT_NONE };
  FpiDeviceAction action;
  int ret;

  if (condition & (G_IO_ERR | G_IO_HUP))
    {
      stop_listening (self);
      fpi_device_action_error (device,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "the fingerprint device went away"));
      return G_SOURCE_REMOVE;
    }

  ret = gfpia_handle_irq (self->gfpia, &event);
  if (ret)
    {
      stop_listening (self);
      fpi_device_action_error (device,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "cannot read the sensor: %s",
                                                         g_strerror (-ret)));
      return G_SOURCE_REMOVE;
    }

  action = fpi_device_get_current_action (device);
  fp_dbg ("interrupt: kind %d, error %u, remaining %u, group %u, finger %u",
          event.kind, event.error, event.remaining, event.group, event.finger);

  switch (event.kind)
    {
    case GFPIA_EVENT_FINGER_DOWN:
      fpi_device_report_finger_status_changes (device,
                                               FP_FINGER_STATUS_PRESENT,
                                               FP_FINGER_STATUS_NONE);
      return G_SOURCE_CONTINUE;

    case GFPIA_EVENT_FINGER_UP:
      fpi_device_report_finger_status_changes (device,
                                               FP_FINGER_STATUS_NONE,
                                               FP_FINGER_STATUS_PRESENT);
      return G_SOURCE_CONTINUE;

    case GFPIA_EVENT_RETRY:
      if (action == FPI_DEVICE_ACTION_ENROLL)
        fpi_device_enroll_progress (device, self->stages_done, NULL,
                                    fpi_device_retry_new (retry_reason (event.error)));
      else if (action == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_report (device, FPI_MATCH_ERROR, NULL,
                                  fpi_device_retry_new (retry_reason (event.error)));
      else if (action == FPI_DEVICE_ACTION_IDENTIFY)
        fpi_device_identify_report (device, NULL, NULL,
                                    fpi_device_retry_new (retry_reason (event.error)));
      return G_SOURCE_CONTINUE;

    case GFPIA_EVENT_ENROL_PROGRESS:
      /* The application counts down what it still wants. */
      self->stages_done = XIAOMI_PIANO_ENROLL_STAGES - event.remaining;
      fpi_device_enroll_progress (device, self->stages_done, NULL, NULL);
      return G_SOURCE_CONTINUE;

    case GFPIA_EVENT_ENROL_DONE:
      {
        g_autoptr(FpPrint) print = NULL;
        FpPrint *requested = NULL;

          finish_operation (self);

        ret = gfpia_enrol_finish (self->gfpia, event.group, event.finger);
        if (ret)
          {
            fpi_device_enroll_complete (device, NULL,
                                        fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                  "cannot store the finger: %s",
                                                                  g_strerror (-ret)));
            return G_SOURCE_CONTINUE;
          }

        /*
         * Keep whatever the caller filled in - the finger it is, its label -
         * and add the identity the application just handed out.
         */
        fpi_device_get_enroll_data (device, &requested);
        print = g_object_ref (requested);
        {
          g_autofree gchar *user_id = user_id_for_finger (event.finger);

          fpi_print_set_type (print, FPI_PRINT_RAW);
          fpi_print_set_device_stored (print, TRUE);
          fpi_print_fill_from_user_id (print, user_id);
          g_object_set (print, "fpi-data",
                        g_variant_new_uint32 (event.finger), NULL);
        }

        fpi_device_enroll_complete (device, g_steal_pointer (&print), NULL);
        return G_SOURCE_CONTINUE;
      }

    case GFPIA_EVENT_MATCH:
      {
        finish_operation (self);

        if (action == FPI_DEVICE_ACTION_VERIFY)
          {
            FpPrint *expected = NULL;
            guint32 wanted = 0;

            fpi_device_get_verify_data (device, &expected);
            if (finger_for_print (expected, &wanted) && wanted == event.finger)
              fpi_device_verify_report (device, FPI_MATCH_SUCCESS, NULL, NULL);
            else
              fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
            fpi_device_verify_complete (device, NULL);
          }
        else
          {
            GPtrArray *gallery = NULL;
            FpPrint *found = NULL;
            guint i;

            fpi_device_get_identify_data (device, &gallery);
            for (i = 0; gallery && i < gallery->len; i++)
              {
                FpPrint *candidate = g_ptr_array_index (gallery, i);
                guint32 finger = 0;

                if (finger_for_print (candidate, &finger) &&
                    finger == event.finger)
                  {
                    found = candidate;
                    break;
                  }
              }

            fpi_device_identify_report (device, found, NULL, NULL);
            fpi_device_identify_complete (device, NULL);
          }
        return G_SOURCE_CONTINUE;
      }

    case GFPIA_EVENT_NO_MATCH:
      finish_operation (self);
      if (action == FPI_DEVICE_ACTION_VERIFY)
        {
          fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
          fpi_device_verify_complete (device, NULL);
        }
      else
        {
          fpi_device_identify_report (device, NULL, NULL, NULL);
          fpi_device_identify_complete (device, NULL);
        }
      return G_SOURCE_CONTINUE;

    case GFPIA_EVENT_NONE:
    default:
      return G_SOURCE_CONTINUE;
    }
}

static void
start_listening (FpiDeviceXiaomiPiano *self)
{
  if (self->irq_source)
    return;

  self->irq_source = g_unix_fd_add (gfpia_irq_fd (self->gfpia),
                                    G_IO_IN | G_IO_ERR | G_IO_HUP,
                                    on_sensor_interrupt, self);
}

static void
stop_listening (FpiDeviceXiaomiPiano *self)
{
  if (!self->irq_source)
    return;

  g_source_remove (self->irq_source);
  self->irq_source = 0;
}

static void
fpi_device_xiaomi_piano_finalize (GObject *object)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (object);

  stop_listening (self);
  g_clear_pointer (&self->gfpia, gfpia_close);

  G_OBJECT_CLASS (fpi_device_xiaomi_piano_parent_class)->finalize (object);
}

static void
dev_probe (FpDevice *device)
{
  /*
   * There is nothing to ask: either the kernel shim and the trusted
   * environment are both there or this is the wrong machine, and opening will
   * say so. Probing must not power the sensor up.
   */
  fpi_device_probe_complete (device, NULL, NULL, NULL);
}

static void
dev_open (FpDevice *device)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (device);
  int ret;

  /* Already up from an earlier open; see dev_close(). */
  if (self->gfpia)
    {
      fpi_device_open_complete (device, NULL);
      return;
    }

  ret = gfpia_open (XIAOMI_PIANO_FIRMWARE_DIR, &self->gfpia);
  if (ret)
    {
      fpi_device_open_complete (device,
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "cannot bring the sensor up: %s",
                                                          g_strerror (-ret)));
      return;
    }

  /*
   * The watch belongs to the device, not to one operation. An interrupt that
   * nobody reads is never acknowledged, and the sensor's line stays asserted:
   * with edge triggering that is the last interrupt there will ever be. The
   * finger lifting after a match is exactly such an interrupt.
   */
  start_listening (self);

  fpi_device_open_complete (device, NULL);
}

static void
dev_close (FpDevice *device)
{
  /*
   * The application stays loaded and the sensor stays up.
   *
   * fprintd opens and closes the device around every operation, and bringing
   * the sensor up costs a full initialisation sequence, so there is nothing to
   * gain by doing it here. What this owns is released when the device is
   * finalised instead - and even then the application itself is left resident,
   * for the reason in gfpia_close().
   */
  fpi_device_close_complete (device, NULL);
}

static void
dev_enroll (FpDevice *device)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (device);
  int ret;

  fp_dbg ("enroll requested");

  self->stages_done = 0;

  ret = gfpia_enrol_begin (self->gfpia, XIAOMI_PIANO_GROUP);
  if (ret)
    {
      fpi_device_enroll_complete (device, NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "cannot start enrolling: %s",
                                                            g_strerror (-ret)));
      return;
    }
}

static void
dev_verify_identify (FpDevice *device)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);
  int ret;

  fp_dbg ("verify or identify requested");

  ret = gfpia_verify_begin (self->gfpia, XIAOMI_PIANO_GROUP);
  if (ret)
    {
      g_autoptr(GError) error =
        fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                  "cannot start matching: %s",
                                  g_strerror (-ret));

      if (action == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_complete (device, g_steal_pointer (&error));
      else
        fpi_device_identify_complete (device, g_steal_pointer (&error));
      return;
    }
}

static void
dev_list (FpDevice *device)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (device);
  g_autoptr(GPtrArray) prints = NULL;
  guint32 groups[GFPIA_MAX_FINGERS];
  guint32 fingers[GFPIA_MAX_FINGERS];
  size_t count = 0;
  size_t i;
  int ret;

  fp_dbg ("list requested");

  ret = gfpia_list (self->gfpia, groups, fingers, GFPIA_MAX_FINGERS, &count);
  if (ret)
    {
      fpi_device_list_complete (device, NULL,
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "cannot read the stored fingers: %s",
                                                          g_strerror (-ret)));
      return;
    }

  prints = g_ptr_array_new_with_free_func (g_object_unref);
  for (i = 0; i < count; i++)
    g_ptr_array_add (prints, print_for_finger (device, fingers[i]));

  fpi_device_list_complete (device, g_steal_pointer (&prints), NULL);
}

static void
dev_delete (FpDevice *device)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (device);
  FpPrint *print = NULL;
  guint32 finger = 0;
  int ret;

  fp_dbg ("delete requested");

  fpi_device_get_delete_data (device, &print);
  if (!finger_for_print (print, &finger))
    {
      fpi_device_delete_complete (device,
                                  fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }

  ret = gfpia_delete (self->gfpia, XIAOMI_PIANO_GROUP, finger);
  if (ret)
    {
      fpi_device_delete_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "cannot forget the finger: %s",
                                                            g_strerror (-ret)));
      return;
    }

  fpi_device_delete_complete (device, NULL);
}

static void
dev_clear_storage (FpDevice *device)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (device);
  guint32 groups[GFPIA_MAX_FINGERS];
  guint32 fingers[GFPIA_MAX_FINGERS];
  size_t count = 0;
  size_t i;
  int ret;

  ret = gfpia_list (self->gfpia, groups, fingers, GFPIA_MAX_FINGERS, &count);
  if (ret)
    {
      fpi_device_clear_storage_complete (device,
                                         fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                   "cannot read the stored fingers: %s",
                                                                   g_strerror (-ret)));
      return;
    }

  for (i = 0; i < count; i++)
    {
      ret = gfpia_delete (self->gfpia, groups[i], fingers[i]);
      if (ret)
        {
          fpi_device_clear_storage_complete (device,
                                             fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                       "cannot forget a finger: %s",
                                                                       g_strerror (-ret)));
          return;
        }
    }

  fpi_device_clear_storage_complete (device, NULL);
}

static void
dev_cancel (FpDevice *device)
{
  FpiDeviceXiaomiPiano *self = FPI_DEVICE_XIAOMI_PIANO (device);
  int ret;

  fp_dbg ("cancel requested");

  if (!self->gfpia)
    return;

  ret = gfpia_cancel (self->gfpia);
  if (ret)
    fp_dbg ("the application would not drop the operation: %s",
            g_strerror (-ret));

  /*
   * Telling the application to stop is only half of it. libfprint asks for a
   * cancel and then waits for the driver to say the action is over; leaving it
   * outstanding wedges fprintd, which cannot release a claim while an
   * operation is running, and every later claim fails with AlreadyInUse until
   * the daemon is restarted.
   */
  if (fpi_device_get_current_action (device) != FPI_DEVICE_ACTION_NONE)
    fpi_device_action_error (device,
                             g_error_new_literal (G_IO_ERROR,
                                                  G_IO_ERROR_CANCELLED,
                                                  "the fingerprint operation was cancelled"));
}

static const FpIdEntry id_table[] = {
  { .virtual_envvar = "FP_XIAOMI_PIANO" },
  { .virtual_envvar = NULL }
};

static void
fpi_device_xiaomi_piano_init (FpiDeviceXiaomiPiano *self)
{
}

static void
fpi_device_xiaomi_piano_class_init (FpiDeviceXiaomiPianoClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_xiaomi_piano_finalize;

  dev_class->id = "xiaomi_piano";
  dev_class->full_name = "Xiaomi Pad 8 Pro side fingerprint reader";
  dev_class->type = FP_DEVICE_TYPE_VIRTUAL;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = XIAOMI_PIANO_ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;

  dev_class->features = FP_DEVICE_FEATURE_IDENTIFY |
                        FP_DEVICE_FEATURE_VERIFY |
                        FP_DEVICE_FEATURE_STORAGE |
                        FP_DEVICE_FEATURE_STORAGE_LIST |
                        FP_DEVICE_FEATURE_STORAGE_DELETE |
                        FP_DEVICE_FEATURE_STORAGE_CLEAR |
                        FP_DEVICE_FEATURE_DUPLICATES_CHECK;

  dev_class->probe = dev_probe;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify_identify;
  dev_class->identify = dev_verify_identify;
  dev_class->list = dev_list;
  dev_class->delete = dev_delete;
  dev_class->clear_storage = dev_clear_storage;
  dev_class->cancel = dev_cancel;
}
