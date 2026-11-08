// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The Linux side of a Xiaomi side fingerprint sensor whose transactions
 * belong to the secure world.
 *
 * Linux never sees an image or a template: the trusted application talks to
 * the sensor over an SPI bus that TrustZone owns. What is left on this side is
 * a supply, a reset line and an interrupt, so that is all this driver has.
 *
 * It is a UIO device rather than a chardev of its own invention, because
 * "deliver an interrupt to userspace" is what UIO is for and it already has
 * the shape this needs: read() blocks until the event count moves, poll()
 * works, and open()/release() are hooked to runtime PM - which is where the
 * supply and the reset line are driven. There is no ioctl at all.
 *
 * uio_pdrv_genirq would very nearly do instead, but binding it means claiming
 * its single of_id module parameter for this sensor, and then nobody on the
 * machine can use it for anything else.
 */

#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/pm_wakeirq.h>
#include <linux/property.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>
#include <linux/uio_driver.h>

#define XIAOMI_FP_UIO_NAME	"xiaomi-fp-uio"

/*
 * Long enough that a finger arriving during suspend keeps the machine up until
 * whoever is listening has been scheduled and has asked the trusted
 * application what happened.
 */
#define XIAOMI_FP_WAKE_MS	2000

/* Held low then high around power-up, per the vendor's sequence. */
#define XIAOMI_FP_RESET_MS	10

/* The supply needs this long to be worth talking to. */
#define XIAOMI_FP_SUPPLY_SETTLE_US	1000

struct xiaomi_fp_uio {
	struct device *dev;
	struct uio_info info;
	struct regulator *vdd;
	struct gpio_desc *reset_gpio;
	struct gpio_desc *irq_gpio;
	/* Serialises the interrupt's masked state against userspace. */
	struct mutex lock;
	int irq;
	bool irq_enabled;
};

static void xiaomi_fp_reset(struct xiaomi_fp_uio *fp)
{
	gpiod_set_value_cansleep(fp->reset_gpio, 1);
	msleep(XIAOMI_FP_RESET_MS);
	gpiod_set_value_cansleep(fp->reset_gpio, 0);
	msleep(XIAOMI_FP_RESET_MS);
}

/**
 * xiaomi_fp_set_irq() - Mask or unmask the sensor's interrupt.
 * @fp: sensor.
 * @enable: whether the line should be able to fire.
 *
 * Idempotent, because enable_irq() and disable_irq() are counted and userspace
 * is under no obligation to keep the two balanced.
 *
 * Context: Caller holds @fp->lock.
 */
static void xiaomi_fp_set_irq(struct xiaomi_fp_uio *fp, bool enable)
{
	if (fp->irq_enabled == enable)
		return;

	if (enable)
		enable_irq(fp->irq);
	else
		disable_irq(fp->irq);

	fp->irq_enabled = enable;
}

static irqreturn_t xiaomi_fp_irq_thread(int irq, void *data)
{
	struct xiaomi_fp_uio *fp = data;

	/*
	 * The line is edge triggered and the sensor is acknowledged over the
	 * secure world, not by a register write from here, so - unlike
	 * uio_pdrv_genirq - there is nothing to mask and nothing for userspace
	 * to re-arm. Interrupts keep arriving whether or not anyone read the
	 * last one.
	 */
	uio_event_notify(&fp->info);
	pm_wakeup_event(fp->dev, XIAOMI_FP_WAKE_MS);

	return IRQ_HANDLED;
}

static int xiaomi_fp_uio_open(struct uio_info *info, struct inode *inode)
{
	struct xiaomi_fp_uio *fp = info->priv;
	int ret;

	ret = pm_runtime_resume_and_get(fp->dev);
	if (ret)
		return ret;

	mutex_lock(&fp->lock);
	xiaomi_fp_set_irq(fp, true);
	mutex_unlock(&fp->lock);

	return 0;
}

static int xiaomi_fp_uio_release(struct uio_info *info, struct inode *inode)
{
	struct xiaomi_fp_uio *fp = info->priv;

	/*
	 * UIO counts openers, so this runs when the last one goes - including
	 * when it went by dying partway through an operation, which is the case
	 * that used to leave the supply on until the next reboot.
	 */
	mutex_lock(&fp->lock);
	xiaomi_fp_set_irq(fp, false);
	mutex_unlock(&fp->lock);

	pm_runtime_put_sync(fp->dev);

	return 0;
}

/**
 * xiaomi_fp_uio_irqcontrol() - write() on the UIO device.
 * @info: UIO device.
 * @irq_on: what userspace wrote.
 *
 * This is the only control this device has, and it exists so that a listener
 * can stop the sensor bothering it without closing the device and dropping the
 * supply.
 *
 * Return: Zero always; there is no way for this to fail.
 */
static int xiaomi_fp_uio_irqcontrol(struct uio_info *info, s32 irq_on)
{
	struct xiaomi_fp_uio *fp = info->priv;

	mutex_lock(&fp->lock);
	xiaomi_fp_set_irq(fp, !!irq_on);
	mutex_unlock(&fp->lock);

	return 0;
}

static int xiaomi_fp_runtime_resume(struct device *dev)
{
	struct xiaomi_fp_uio *fp = dev_get_drvdata(dev);
	int ret;

	ret = regulator_enable(fp->vdd);
	if (ret)
		return ret;

	usleep_range(XIAOMI_FP_SUPPLY_SETTLE_US,
		     XIAOMI_FP_SUPPLY_SETTLE_US + 100);
	xiaomi_fp_reset(fp);

	return 0;
}

static int xiaomi_fp_runtime_suspend(struct device *dev)
{
	struct xiaomi_fp_uio *fp = dev_get_drvdata(dev);

	/*
	 * Into reset before the supply goes, so the sensor is never left
	 * driving pins from a rail that is on its way down.
	 */
	gpiod_set_value_cansleep(fp->reset_gpio, 1);

	return regulator_disable(fp->vdd);
}

static const struct dev_pm_ops xiaomi_fp_pm_ops = {
	RUNTIME_PM_OPS(xiaomi_fp_runtime_suspend, xiaomi_fp_runtime_resume,
		       NULL)
};

static int xiaomi_fp_uio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct xiaomi_fp_uio *fp;
	int ret;

	fp = devm_kzalloc(dev, sizeof(*fp), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;

	fp->dev = dev;
	mutex_init(&fp->lock);
	platform_set_drvdata(pdev, fp);

	fp->vdd = devm_regulator_get(dev, "vdd");
	if (IS_ERR(fp->vdd))
		return dev_err_probe(dev, PTR_ERR(fp->vdd),
				     "failed to get vdd supply\n");

	fp->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(fp->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(fp->reset_gpio),
				     "failed to get reset GPIO\n");

	fp->irq_gpio = devm_gpiod_get(dev, "irq", GPIOD_IN);
	if (IS_ERR(fp->irq_gpio))
		return dev_err_probe(dev, PTR_ERR(fp->irq_gpio),
				     "failed to get IRQ GPIO\n");

	fp->irq = gpiod_to_irq(fp->irq_gpio);
	if (fp->irq < 0)
		return dev_err_probe(dev, fp->irq, "failed to map IRQ GPIO\n");

	/*
	 * IRQF_NO_AUTOEN: the line stays masked until something opens the
	 * device. An interrupt raised while the sensor is unpowered would say
	 * nothing anyway, and nobody would be listening for it.
	 */
	ret = devm_request_threaded_irq(dev, fp->irq, NULL,
					xiaomi_fp_irq_thread,
					IRQF_TRIGGER_RISING | IRQF_ONESHOT |
					IRQF_NO_AUTOEN,
					XIAOMI_FP_UIO_NAME, fp);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request IRQ\n");

	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return dev_err_probe(dev, ret, "failed to enable runtime PM\n");

	/*
	 * No memory maps: there is nothing on this side to map. UIO is fine
	 * with that, and UIO_IRQ_CUSTOM says the interrupt is this driver's to
	 * own - which it has to be, because a wake IRQ cannot be handed to the
	 * UIO core.
	 */
	fp->info.name = XIAOMI_FP_UIO_NAME;
	fp->info.version = "1";
	fp->info.irq = UIO_IRQ_CUSTOM;
	fp->info.open = xiaomi_fp_uio_open;
	fp->info.release = xiaomi_fp_uio_release;
	fp->info.irqcontrol = xiaomi_fp_uio_irqcontrol;
	fp->info.priv = fp;

	ret = devm_uio_register_device(dev, &fp->info);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to register UIO device\n");

	if (device_property_read_bool(dev, "wakeup-source")) {
		ret = devm_device_init_wakeup(dev);
		if (ret)
			return dev_err_probe(dev, ret,
					     "failed to mark as wakeup source\n");

		ret = dev_pm_set_wake_irq(dev, fp->irq);
		if (ret)
			dev_warn(dev, "no wake IRQ, a finger will not wake the machine: %d\n",
				 ret);
	}

	return 0;
}

static void xiaomi_fp_uio_remove(struct platform_device *pdev)
{
	dev_pm_clear_wake_irq(&pdev->dev);
}

static const struct of_device_id xiaomi_fp_uio_of_match[] = {
	/* The sensor itself, which is what a device tree should be naming. */
	{ .compatible = "goodix,gf3656zs1" },
	/* What the shipped device tree calls it. */
	{ .compatible = "xiaomi,xiaomi-fp" },
	{ }
};
MODULE_DEVICE_TABLE(of, xiaomi_fp_uio_of_match);

static struct platform_driver xiaomi_fp_uio_driver = {
	.probe = xiaomi_fp_uio_probe,
	.remove = xiaomi_fp_uio_remove,
	.driver = {
		.name = XIAOMI_FP_UIO_NAME,
		.of_match_table = xiaomi_fp_uio_of_match,
		.pm = pm_ptr(&xiaomi_fp_pm_ops),
	},
};
module_platform_driver(xiaomi_fp_uio_driver);

MODULE_AUTHOR("BigfootACA");
MODULE_DESCRIPTION("UIO interface to a TrustZone-owned Xiaomi fingerprint sensor");
MODULE_LICENSE("GPL");
