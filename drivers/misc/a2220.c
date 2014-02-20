/* drivers/i2c/chips/a2220.c - a2220 voice processor driver
 *
 * Copyright (C) 2009 HTC Corporation.
 *
 * Complete rewrite,  anish kumar (anish.singh@samsung.com)
 * Complete rewrite (again), Ryan Pennucci <decimalman@gmail.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/i2c.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <sound/a2220.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <mach/msm_xo.h>

#include "a2220_firmware.h"

struct a2220_drv {
	struct i2c_client		*client;
	struct a2220_platform_data	*pdata;
	struct mutex			lock;
	struct miscdevice		device;
	struct delayed_work		init_work;
	atomic_t			opened;
	bool				suspended;
	unsigned int			config;
	struct msm_xo_voter		*xo;
};

static int a2220_i2c_read(struct a2220_drv *a2220, char *buf, int len) {
	int rc;
	struct i2c_msg msgs[] = {
		{
			.addr = a2220->client->addr,
			.flags = I2C_M_RD,
			.len = len,
			.buf = buf,
		},
	};

	rc = i2c_transfer(a2220->client->adapter, msgs, 1);
	if (rc <= 0)
		pr_err("%s: read error\n", __func__);
	return rc;
}
static int a2220_i2c_write(struct a2220_drv *a2220, char *buf, int len) {
	int rc;
	struct i2c_msg msgs[] = {
		{
			.addr = a2220->client->addr,
			.flags = 0,
			.len = len,
			.buf = buf,
		},
	};

	rc = i2c_transfer(a2220->client->adapter, msgs, 1);
	if (rc < 0)
		pr_err("%s: write error\n", __func__);
	return rc;
}

static int a2220_send_msg(struct a2220_drv *a2220, const char *msg) {
	int rc;
	char buf[4];
	int retry;

	memcpy(buf, msg, 4);

	rc = a2220_i2c_write(a2220, buf, 4);
	if (rc < 0) {
		pr_err("%s: send cmd returned %i\n", __func__, rc);
		return rc;
	}

	if (!memcmp(msg, suspend_mode, 4)) {
		rc = a2220_i2c_read(a2220, buf, 4);
		if (rc < 0) {
			a2220->suspended = 1;
			return 0;
		}
		pr_warn("%s: standby rejected, rc %i, %02x%02x%02x%02x\n",
			__func__, rc, buf[0], buf[1], buf[2], buf[3]);
		return -EAGAIN;
	}

	retry = 4;
	while (--retry) {
		rc = a2220_i2c_read(a2220, buf, 4);

		if (rc == -ENOTCONN || rc == -ETIMEDOUT) {
			printk(KERN_DEBUG "%s: chip isn't responding\n",
				__func__);
			msleep(20);
			continue;
		}
		if (rc < 0) {
			printk(KERN_DEBUG "%s: read fail, retrying\n",
				__func__);
			msleep(10);
			continue;
		}

		if (buf[0] == 0x80 && buf[1] == msg[1]) {
			rc = 0;
		} else if (buf[0] == 0xff && buf[1] == 0xff) {
			pr_err("%s: illegal cmd %02x%02x%02x%02x\n", __func__,
				msg[0], msg[1], msg[2], msg[3]);
			rc = -EINVAL;
		} else if (buf[0] == 0x00 && buf[1] == 0x00) {
			pr_warn("%s: not ready\n", __func__);
			rc = -EAGAIN;
		} else {
			pr_err("%s: unknown response, retry\n", __func__);
			msleep(10);
			rc = -EFAULT;
			continue;
		}
		break;
	}

	return rc;
}

static int a2220_hw_sync(struct a2220_drv *a2220) {
	int rc;
	int retry = 4;
	while (--retry) {
		msleep(20);
		if (!(rc = a2220_send_msg(a2220, sync_chip)))
			break;
		/*
		if (retry == 2 && a2220_send_msg(a2220, reset_chip))
			pr_warn("%s: reset_chip failed!\n", __func__);
		*/
		pr_warn("%s: sync failed, retrying\n", __func__);
	}
	return rc;
}

static int a2220_hw_init(struct a2220_drv *a2220) {
	int rc;
	char buf[2] = { A2220_msg_BOOT >> 8, A2220_msg_BOOT & 0xff };
	int remain;
	char *index;

	gpio_set_value(a2220->pdata->gpio_reset, 0);
	msleep(1);
	gpio_set_value(a2220->pdata->gpio_reset, 1);
	msleep(50);

	a2220->config = A2220_PATH_MAX;

	rc = a2220_i2c_write(a2220, buf, 2);
	if (rc < 0) {
		pr_err("%s: couldn't send boot msg\n", __func__);
		return rc;
	}

	msleep(1);
	rc = a2220_i2c_read(a2220, buf, 1);
	if (rc < 0) {
		pr_err("%s: didn't get boot ack\n", __func__);
		return rc;
	}

	index = a2220_firmware_buf;
	remain = sizeof(a2220_firmware_buf); 
	while (remain) {
		int to_write = 32;
		if (to_write > remain)
			to_write = remain;
		rc = a2220_i2c_write(a2220, index, to_write);
		if (rc < 0)
			break;
		index += to_write;
		remain -= to_write;
	}

	if (rc < 0) {
		pr_err("%s: error writing firmware\n", __func__);
		return rc;
	}

	msleep(30);
	rc = a2220_hw_sync(a2220);
	if (!rc)
		a2220->suspended = 0;
	return rc;
}

static int a2220_set_config(struct a2220_drv *a2220, unsigned int newid) {
	int rc = 0;
	int retry;
	char *msg;
	int size;

	pr_warn("%s: setting path %i\n", __func__, newid);
	if (unlikely(a2220->config == newid))
		return 0;
	if (unlikely(newid >= A2220_PATH_MAX))
		return -EINVAL;

	if (!a2220->suspended)
		goto resumed;

	pr_warn("%s: kicking chip\n", __func__);
	gpio_set_value(a2220->pdata->gpio_wakeup, 0);
	rc = a2220_hw_sync(a2220);
	gpio_set_value(a2220->pdata->gpio_wakeup, 1);

	if (rc) {
		pr_warn("%s: sync failed, resetting chip\n", __func__);
		if (rc = a2220_hw_init(a2220))
			return rc;
	}
	a2220->suspended = 0;

resumed:
	pr_warn("%s: chip is resumed\n", __func__);
	msg = a2220_config_params[newid].data;
	size = a2220_config_params[newid].len;
	while (size) {
		for (retry = 4; retry; retry--) {
			if (!(rc = a2220_send_msg(a2220, msg)))
				break;
		}
		if (!retry) {
			pr_err("%s: send_cmd failed\n", __func__);
		}
		msg += 4;
		size -= 4;
	}
	if (!rc)
		a2220->config = newid;
	return rc;
}

static void a2220_init_work(struct work_struct *work) {
	struct a2220_drv *a2220 = container_of(work,
		struct a2220_drv, init_work.work);
	mutex_lock(&a2220->lock);
	msm_xo_mode_vote(a2220->xo, MSM_XO_MODE_ON);

	if (a2220_hw_init(a2220))
		pr_err("%s: couldn't init hw\n", __func__);
	else if (a2220_set_config(a2220, A2220_PATH_INCALL_RECEIVER_NSOFF))
		pr_err("%s: couldn't bypass\n", __func__);

	msm_xo_mode_vote(a2220->xo, MSM_XO_MODE_OFF);
	mutex_unlock(&a2220->lock);
}

static int a2220_open(struct inode *inode, struct file *file) {
	struct a2220_drv *a2220 = container_of(file->private_data,
		struct a2220_drv, device);
	if (atomic_xchg(&a2220->opened, 1))
		return -EBUSY;
	return 0;
}

static int a2220_release(struct inode *inode, struct file *file) {
	struct a2220_drv *a2220 = container_of(file->private_data,
		struct a2220_drv, device);
	atomic_set(&a2220->opened, 0);
	return 0;
}

static long a2220_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg) {
	struct a2220_drv *a2220 = container_of(file->private_data,
		struct a2220_drv, device);
	long rc = 0;

	mutex_lock(&a2220->lock);

	switch (cmd) {
	case A2220_BOOTUP_INIT:
		pr_warn("%s: ignoring reinitialization request\n", __func__);
		//schedule_delayed_work(&a2220->init_work, 0);
		break;

	case A2220_SET_CONFIG:
		msm_xo_mode_vote(a2220->xo, MSM_XO_MODE_ON);
		rc = a2220_set_config(a2220, arg);
		msm_xo_mode_vote(a2220->xo, MSM_XO_MODE_OFF);
		break;

	case A2220_SET_NS_STATE:
		pr_warn("%s: no-op supression ioctl\n", __func__);
		break;

	default:
		pr_err("%s: invalid ioctl %i\n", __func__, _IOC_NR(cmd));
		rc = -EINVAL;
	}
	mutex_unlock(&a2220->lock);
	if (rc)
		printk(KERN_DEBUG "%s: returning %li\n", __func__, rc);
	return rc;
}

static const struct file_operations a2220_fops = {
        .owner = THIS_MODULE,
        .open = a2220_open,
        .release = a2220_release,
        .unlocked_ioctl = a2220_ioctl,
};

static int a2220_probe(struct i2c_client *client,
		const struct i2c_device_id *id) {
	int rc = 0;
	struct a2220_drv *a2220;
	struct a2220_platform_data *pdata;

	pdata = client->dev.platform_data;
	if (!pdata) {
		pr_err("%s: missing platform data!\n", __func__);
		rc = -ENODEV;
		goto out_no_pdata;
	}

	if (!pdata->a2220_hw_init) {
		pr_err("%s: missing a2220_hw_init!\n", __func__);
		rc = -ENODEV;
		goto out_no_pdata;
	}

	if (rc = pdata->a2220_hw_init())
		goto out_no_pdata;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("%s: i2c missing functionality!\n", __func__);
		rc = -ENODEV;
		goto out_no_pdata;
	}

	a2220 = kzalloc(sizeof(struct a2220_drv), GFP_KERNEL);
	if (!a2220) {
		pr_err("%s: can't allocate memory!\n", __func__);
		rc = -ENOMEM;
		goto out_no_pdata;
	}

	a2220->device.minor = MISC_DYNAMIC_MINOR;
	a2220->device.name = "audience_a2220";
	a2220->device.fops = &a2220_fops;
	if (rc = misc_register(&a2220->device)) {
		pr_err("%s: register device failed!\n", __func__);
		goto out_no_pdata;
	}

	a2220->xo = msm_xo_get(MSM_XO_CXO, "audio_driver");
	if (!a2220->xo) {
		pr_err("%s: couldn't get XO!\n", __func__);
		rc = -EAGAIN;
		goto out_no_xo;
	}

	INIT_DELAYED_WORK(&a2220->init_work, a2220_init_work);
	a2220->client = client;
	a2220->pdata = pdata;
	mutex_init(&a2220->lock);
	i2c_set_clientdata(client, a2220);

	schedule_delayed_work(&a2220->init_work, HZ);

	return rc;

out_no_xo:
	misc_deregister(&a2220->device);
out_no_pdata:
	return rc;
}

static int a2220_remove(struct i2c_client *client) {
	struct a2220_drv *a2220 = i2c_get_clientdata(client);
	misc_deregister(&a2220->device);
	mutex_destroy(&a2220->lock);
	msm_xo_put(a2220->xo);
	kfree(a2220);
	return 0;
}

static int a2220_suspend(struct i2c_client *client, pm_message_t mesg)
{
	struct a2220_drv *a2220 = i2c_get_clientdata(client);
	if (unlikely(!a2220->suspended || a2220->config == A2220_PATH_MAX)) {
		pr_warn("%s: trying to suspend\n", __func__);
		msm_xo_mode_vote(a2220->xo, MSM_XO_MODE_ON);
		if (a2220_set_config(a2220, A2220_PATH_INCALL_RECEIVER_NSOFF))
			pr_warn("%s: couldn't suspend a2220!\n", __func__);
		msm_xo_mode_vote(a2220->xo, MSM_XO_MODE_OFF);
	}
        return 0;
}

static int a2220_resume(struct i2c_client *client)
{
        return 0;
}

static const struct i2c_device_id a2220_id[2] = {
        { "audience_a2220", 0 },
};

static struct i2c_driver a2220_driver = {
        .probe = a2220_probe,
        .remove = a2220_remove,
        .suspend = a2220_suspend,
        .resume = a2220_resume,
        .id_table = a2220_id,
        .driver = {
                .name = "audience_a2220",
        },
};

static int __init a2220_init(void) {
	return i2c_add_driver(&a2220_driver);
}

static void __exit a2220_exit(void) {
	i2c_del_driver(&a2220_driver);
}

module_init(a2220_init);
module_exit(a2220_exit);

MODULE_DESCRIPTION("A2220 voice processor driver");
MODULE_LICENSE("GPL");
