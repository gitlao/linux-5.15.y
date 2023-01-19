/*
 * Pericom PT7C4337 RTC Driver
 *
 * Copyright (c) 2021 Guangzhou Lango Electronics Technology Co.,Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 * 
 * 2021-02-24 pgz:
 *		1. add alarm irq, and clear alarm interrupt flag.
 *		2. add alarm read and alarm intterrupt enable api.
 */

#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/i2c.h>
#include <linux/bitrev.h>
#include <linux/bcd.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define PT7C4337_BYTE_SECS	0
#define PT7C4337_BYTE_MINS	1
#define PT7C4337_BYTE_HOURS	2
#define PT7C4337_BYTE_WDAY	3
#define PT7C4337_BYTE_DAY	4
#define PT7C4337_BYTE_MONTH	5
#define PT7C4337_BYTE_YEAR	6


#define PT7C4337_ALARM_BYTE_SECS      0
#define PT7C4337_ALARM_BYTE_MINS      1
#define PT7C4337_ALARM_BYTE_HOURS     2
#define PT7C4337_ALARM_BYTE_DAY       3


#define PT7C4337_ALARM_REG_SECS       0x07
#define PT7C4337_ALARM_REG_MINS       0x08
#define PT7C4337_ALARM_REG_HOURS      0x09
#define PT7C4337_ALARM_REG_DAY        0x0A


#define PT7C4337_CMD_CONTROL	0x0e
#define PT7C4337_CMD_STATUS		0x0f

#define PT7C4337_A1F_MASK       0x01
#define PT7C4337_A1E_MASK       0x01

/* flags for STATUS */
#define PT7C4337_HOURS_24H		0x40
#define PT7C4337_STATUS_OSF		0x80
#define PT7C4337_CONTROL_ETIME	0x80

static const struct i2c_device_id pt7c4337_id[] = {
	{ "pt7c4337", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, pt7c4337_id);

#ifdef CONFIG_OF
static const struct of_device_id pt7c4337_of_match[] = {
	{ .compatible = "pericom,pt7c4337" },
	{}
};
MODULE_DEVICE_TABLE(of, pt7c4337_of_match);
#endif

struct pt7c4337 {
	struct i2c_client *client;
	struct rtc_device *rtc;
	int twentyfourhour;
};

static int pt7c4337_set_reg(struct pt7c4337 *pt7c4337, char *buf, int len)
{
	struct i2c_client *client = pt7c4337->client;
	int ret = i2c_smbus_write_i2c_block_data(client, buf[0], len-1, &buf[1]);

	if (ret < 0)
		return ret;
	return 0;
}

static int pt7c4337_get_reg(struct pt7c4337 *pt7c4337, char reg, char *buf, int len)
{
	struct i2c_client *client = pt7c4337->client;
	int ret = i2c_smbus_read_i2c_block_data(client, reg, len, buf);

	if (ret < 0)
		return ret;
	return 0;
}

/*
 * Returns <0 on error, 0 if rtc is setup fine and 1 if the chip was reset.
 * To keep the information if an irq is pending, pass the value read from
 * STATUS1 to the caller.
 */
static int pt7c4337_init(struct pt7c4337 *pt7c4337, char *status)
{
	char buf[2];
	int ret;
	//Enable oscillator and time count chain
	buf[0] = PT7C4337_CMD_CONTROL;
	buf[1] = 0x1D;
	ret = pt7c4337_set_reg(pt7c4337, buf, 2);
	if (ret < 0)
		return ret;

	//clear Oscillator Stop Flag
	buf[0] = PT7C4337_CMD_STATUS;
	buf[1] = 0;
	ret = pt7c4337_set_reg(pt7c4337, buf, 2);
	if (ret < 0)
		return ret;

	//set 24 hour mode
	*status = 0;
	ret = pt7c4337_get_reg(pt7c4337, PT7C4337_BYTE_HOURS, status, 1);
	if (ret < 0)
		return ret;

	*status &= ~PT7C4337_HOURS_24H;
	buf[0] = PT7C4337_BYTE_HOURS;
	buf[1] = *status;
	ret = pt7c4337_set_reg(pt7c4337, buf, 2);

	if (ret < 0)
		return ret;

	return 1;
}

static char pt7c4337_hr2reg(struct pt7c4337 *pt7c4337, int hour)
{
	if (pt7c4337->twentyfourhour)
		return bin2bcd(hour);

	if (hour < 12)
		return bin2bcd(hour);

	return 0x40 | bin2bcd(hour - 12);
}

static int pt7c4337_reg2hr(struct pt7c4337 *pt7c4337, char reg)
{
	unsigned hour;

	if (pt7c4337->twentyfourhour)
		return bcd2bin(reg & 0x3f);

	hour = bcd2bin(reg & 0x1f);
	if (reg & 0x40)
		hour += 12;

	return hour;
}

static int pt7c4337_set_datetime(struct i2c_client *client, struct rtc_time *tm)
{
	struct pt7c4337	*pt7c4337 = i2c_get_clientdata(client);
	int err;
	char buf[8];

	/* Years <= 19XX is to early, and 2038 is too far for Android */
	if (tm->tm_year < 100 || tm->tm_year > 137)
		return -EINVAL;

	printk("[rtcTime-pt7c4337-set]: %4d-%02d-%02d(%d) %02d:%02d:%02d\n",
		1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday, tm->tm_wday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);

	buf[0] = PT7C4337_BYTE_SECS;
	buf[1+PT7C4337_BYTE_YEAR] = bin2bcd(tm->tm_year - 100);
	buf[1+PT7C4337_BYTE_MONTH] = bin2bcd(tm->tm_mon + 1);
	buf[1+PT7C4337_BYTE_DAY] = bin2bcd(tm->tm_mday);
	buf[1+PT7C4337_BYTE_WDAY] = bin2bcd(tm->tm_wday + 1);
	buf[1+PT7C4337_BYTE_HOURS] = pt7c4337_hr2reg(pt7c4337, tm->tm_hour);
	buf[1+PT7C4337_BYTE_MINS] = bin2bcd(tm->tm_min);
	buf[1+PT7C4337_BYTE_SECS] = bin2bcd(tm->tm_sec);

	err = pt7c4337_set_reg(pt7c4337, buf, sizeof(buf));

	return err;
}

static int pt7c4337_get_datetime(struct i2c_client *client, struct rtc_time *tm)
{
	struct pt7c4337 *pt7c4337 = i2c_get_clientdata(client);
	char buf[7];
	int err;

	err = pt7c4337_get_reg(pt7c4337, PT7C4337_BYTE_SECS, buf, sizeof(buf));
	if (err < 0)
		return err;

	tm->tm_sec = bcd2bin(buf[PT7C4337_BYTE_SECS]);
	tm->tm_min = bcd2bin(buf[PT7C4337_BYTE_MINS]);
	tm->tm_hour = pt7c4337_reg2hr(pt7c4337, buf[PT7C4337_BYTE_HOURS]);
	tm->tm_wday = bcd2bin(buf[PT7C4337_BYTE_WDAY]) - 1;
	tm->tm_mday = bcd2bin(buf[PT7C4337_BYTE_DAY]);
	tm->tm_mon = bcd2bin(buf[PT7C4337_BYTE_MONTH] & 0x1f) - 1;
	tm->tm_year = bcd2bin(buf[PT7C4337_BYTE_YEAR]) + 100;

	return rtc_valid_tm(tm);
}

static int pt7c4337_alarm_irq_enable(struct i2c_client *client,
					unsigned int enabled)
{
	int ret;

	ret = i2c_smbus_read_byte_data(client, PT7C4337_CMD_CONTROL);
	if (ret < 0)
		return ret;

	if (enabled)
		ret |= PT7C4337_A1E_MASK;
	else
		ret &= ~PT7C4337_A1E_MASK;

	return i2c_smbus_write_byte_data(client, PT7C4337_CMD_CONTROL, ret);
};

static int pt7c4337_set_alarmtime(struct i2c_client *client, struct rtc_wkalrm *alm)
{
	struct pt7c4337 *pt7c4337 = i2c_get_clientdata(client);
	int ret;
	char buf[5];
	struct rtc_time *alm_tm = &alm->time;

	printk("[rtcAlarm-pt7c4337-set]: %4d-%02d-%02d(%d) %02d:%02d:%02d enabled %d\n",
		1900 + alm_tm->tm_year, alm_tm->tm_mon + 1, alm_tm->tm_mday, alm_tm->tm_wday,
		alm_tm->tm_hour, alm_tm->tm_min, alm_tm->tm_sec, alm->enabled);

	/*
	 * The alarm has no seconds so deal with it
	 */
	if (alm_tm->tm_sec) {
		alm_tm->tm_sec = 0;
		alm_tm->tm_min++;
		if (alm_tm->tm_min >= 60) {
			alm_tm->tm_min = 0;
			alm_tm->tm_hour++;
			if (alm_tm->tm_hour >= 24) {
				alm_tm->tm_hour = 0;
				alm_tm->tm_mday++;
				if (alm_tm->tm_mday > 31)
					alm_tm->tm_mday = 0;
			}
		}
	}

	//status reg config
	ret = i2c_smbus_read_byte_data(client, PT7C4337_CMD_STATUS);
	if (ret < 0)
		return ret;

	if (ret & PT7C4337_A1F_MASK)//pgz, clear alarm interrupt flag
	{
		ret &= ~PT7C4337_A1F_MASK;
	}

	ret = i2c_smbus_write_byte_data(client, PT7C4337_CMD_STATUS, ret);
	if (ret < 0)
		return ret;

	buf[0] = PT7C4337_ALARM_REG_SECS;
	buf[1+PT7C4337_ALARM_BYTE_DAY] = bin2bcd(alm_tm->tm_mday);
	buf[1+PT7C4337_ALARM_BYTE_HOURS] = pt7c4337_hr2reg(pt7c4337, alm_tm->tm_hour);
	buf[1+PT7C4337_ALARM_BYTE_MINS] = bin2bcd(alm_tm->tm_min);
	buf[1+PT7C4337_ALARM_BYTE_SECS] = bin2bcd(0x00);

	ret = pt7c4337_set_reg(pt7c4337, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	return pt7c4337_alarm_irq_enable(client, alm->enabled);
}

static int pt7c4337_read_alarmtime(struct i2c_client *client, struct rtc_wkalrm *alm)
{
	struct pt7c4337 *pt7c4337 = i2c_get_clientdata(client);
	char buf[4];
	int ret;

	ret = pt7c4337_get_reg(pt7c4337, PT7C4337_ALARM_REG_SECS, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	/* The alarm only has a minute accuracy */
	alm->time.tm_sec = -1;

	alm->time.tm_min = bcd2bin(buf[PT7C4337_ALARM_BYTE_MINS] & 0x7F);
	alm->time.tm_hour = pt7c4337_reg2hr(pt7c4337, buf[PT7C4337_ALARM_BYTE_HOURS]);
	alm->time.tm_mday = bcd2bin(buf[PT7C4337_ALARM_BYTE_DAY] & 0x3F);
	alm->time.tm_wday = -1;
	alm->time.tm_mon = -1;
	alm->time.tm_year = -1;

	ret = i2c_smbus_read_byte_data(client, PT7C4337_CMD_CONTROL);
	if (ret < 0)
		return ret;

	if (ret & PT7C4337_A1E_MASK)
		alm->enabled = 1;

	return 0;
}

/*
 * The alarm interrupt is implemented as a level-low interrupt in the
 * pt7c4337, while the timer interrupt uses a falling edge.
 * We don't use the timer at all, so the interrupt is requested to
 * use the level-low trigger.
 */
static irqreturn_t pt7c4337_irq(int irq, void *dev_id)
{
	struct pt7c4337 *pt7c4337 = (struct pt7c4337 *)dev_id;
	struct i2c_client *client = pt7c4337->client;
	struct mutex *lock = &pt7c4337->rtc->ops_lock;
	int data, ret;

	printk(">>rtcAlarm-hym8563_irq occured!\n");
	mutex_lock(lock);

	/* Clear the alarm flag */
	data = i2c_smbus_read_byte_data(client, PT7C4337_CMD_STATUS);
	if (data < 0) {
		dev_err(&client->dev, "%s: error reading i2c data %d\n",
			__func__, data);
		goto out;
	}

	data &= ~PT7C4337_A1F_MASK;//clear alarm interrupts flag

	ret = i2c_smbus_write_byte_data(client, PT7C4337_CMD_STATUS, data);
	if (ret < 0) {
		dev_err(&client->dev, "%s: error writing i2c data %d\n",
			__func__, ret);
	}

out:
	mutex_unlock(lock);
	return IRQ_HANDLED;
}

static int pt7c4337_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	return pt7c4337_get_datetime(to_i2c_client(dev), tm);
}

static int pt7c4337_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	return pt7c4337_set_datetime(to_i2c_client(dev), tm);
}

static int pt7c4337_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *tm)
{
	return pt7c4337_set_alarmtime(to_i2c_client(dev), tm);
}

static int pt7c4337_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *tm)
{
	return pt7c4337_read_alarmtime(to_i2c_client(dev), tm);
}

static int pt7c4337_rtc_alarm_irq_enable(struct device *dev, unsigned int enabled)
{
	return pt7c4337_alarm_irq_enable(to_i2c_client(dev), enabled);
}

static const struct rtc_class_ops pt7c4337_rtc_ops = {
	.read_time	= pt7c4337_rtc_read_time,
	.set_time	= pt7c4337_rtc_set_time,
	.alarm_irq_enable = pt7c4337_rtc_alarm_irq_enable,
	.set_alarm	= pt7c4337_rtc_set_alarm,
	.read_alarm	= pt7c4337_rtc_read_alarm,
};

static struct i2c_driver pt7c4337_driver;

static int pt7c4337_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	int err;
	struct pt7c4337 *pt7c4337;
	char status;
	struct rtc_time tm_read, tm = {
		.tm_wday = 0,
		.tm_year = 121,//default time to 2021
		.tm_mon = 0,
		.tm_mday = 1,
		.tm_hour = 12,
		.tm_min = 0,
		.tm_sec = 0,
	};

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		err = -ENODEV;
		goto exit;
	}

	pt7c4337 = devm_kzalloc(&client->dev, sizeof(struct pt7c4337),
				GFP_KERNEL);
	if (!pt7c4337) {
		err = -ENOMEM;
		goto exit;
	}

	pt7c4337->client = client;
	i2c_set_clientdata(client, pt7c4337);

	err = pt7c4337_init(pt7c4337, &status);
	if (err < 0) {
		dev_err(&client->dev, "error initting chip\n");
		goto exit;
	}

	if (status & PT7C4337_HOURS_24H)
		pt7c4337->twentyfourhour = 0;
	else
		pt7c4337->twentyfourhour = 1;

	if (client->irq > 0) {
		err = devm_request_threaded_irq(&client->dev, client->irq,
						NULL, pt7c4337_irq,
						IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
						client->name, pt7c4337);//lango pgz modify to falling
		if (err < 0) {
			dev_err(&client->dev, "irq %d request failed, %d\n",
				client->irq, err);
			goto exit;
		}
	}

	/* initial time,avoid read time error */
	pt7c4337_rtc_read_time(&client->dev, &tm_read);
	if ( (tm_read.tm_year < 70) | (tm_read.tm_year > 137) | (tm_read.tm_mon == -1) | (rtc_valid_tm(&tm_read) != 0) )
		pt7c4337_rtc_set_time(&client->dev, &tm);
	
	pt7c4337->rtc = devm_rtc_device_register(&client->dev,
					pt7c4337_driver.driver.name,
					&pt7c4337_rtc_ops, THIS_MODULE);

	if (IS_ERR(pt7c4337->rtc)) {
		err = PTR_ERR(pt7c4337->rtc);
		goto exit;
	} 

	/* the pt7c4337 alarm only supports a minute accuracy */
	pt7c4337->rtc->uie_unsupported = 1;

	return 0;

exit:
	return err;
}

static int pt7c4337_remove(struct i2c_client *client)
{
	return 0;
}

static struct i2c_driver pt7c4337_driver = {
	.driver		= {
		.name	= "rtc-pt7c4337",
		.of_match_table = of_match_ptr(pt7c4337_of_match),
	},
	.probe		= pt7c4337_probe,
	.remove		= pt7c4337_remove,
	.id_table	= pt7c4337_id,
};

module_i2c_driver(pt7c4337_driver);

MODULE_DESCRIPTION("PT7C4337 RTC driver");
MODULE_LICENSE("GPL");
