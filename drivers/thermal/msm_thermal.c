/* Copyright (c) 2012, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/mutex.h>
#include <linux/msm_tsens.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>

#define DEF_TEMP_SENSOR      0
#define DEF_THERMAL_CHECK_MS 1000
#define DEF_ALLOWED_MAX_HIGH 60
#define DEF_ALLOWED_MAX_FREQ 918000

static int enabled;
static int allowed_max_high = DEF_ALLOWED_MAX_HIGH;
static int allowed_max_low = (DEF_ALLOWED_MAX_HIGH - 10);
static int allowed_max_freq = DEF_ALLOWED_MAX_FREQ;
static int check_interval_ms = DEF_THERMAL_CHECK_MS;

static DEFINE_SPINLOCK(limits_lock);
DEFINE_PER_CPU(unsigned int, limits);

module_param(allowed_max_high, int, 0);
module_param(allowed_max_freq, int, 0);
module_param(check_interval_ms, int, 0);

static struct delayed_work check_temp_work;

static int update_cpu_max_freq(struct cpufreq_policy *cpu_policy,
			       int cpu, int max_freq)
{
	int ret = 0;

	if (!max_freq)
		return -EINVAL;

	if (!cpu_policy)
		return -EINVAL;

	cpufreq_verify_within_limits(cpu_policy,
				cpu_policy->min, max_freq);
	cpu_policy->user_policy.max = max_freq;

	/* Prevent the policy notifier from using these new limits */
	spin_lock(&limits_lock);
	ret = cpufreq_update_policy(cpu);
	spin_unlock(&limits_lock);
	if (!ret)
		pr_info("msm_thermal: Limiting core%d max frequency to %d\n",
			cpu, max_freq);

	return ret;
}

static void check_temp(struct work_struct *work)
{
	struct cpufreq_policy *cpu_policy = NULL;
	struct tsens_device tsens_dev;
	unsigned long temp = 0;
	unsigned int max_freq = 0;
	int update_policy = 0;
	int cpu = 0;
	int ret = 0;

	tsens_dev.sensor_num = DEF_TEMP_SENSOR;
	ret = tsens_get_temp(&tsens_dev, &temp);
	if (unlikely(ret)) {
		pr_debug("msm_thermal: Unable to read TSENS sensor %d\n",
				tsens_dev.sensor_num);
		goto reschedule;
	}

	for_each_online_cpu(cpu) {
		update_policy = 0;
		cpu_policy = cpufreq_cpu_get(cpu);
		if (!cpu_policy) {
			pr_debug("msm_thermal: NULL policy on cpu %d\n", cpu);
			continue;
		}
		spin_lock(&limits_lock);
		if (temp >= allowed_max_high) {
			if (cpu_policy->max > allowed_max_freq) {
				max_freq = per_cpu(limits, cpu);
				update_policy = 1;
			} else {
				pr_debug("msm_thermal: policy max for cpu %d "
					 "already < allowed_max_freq\n", cpu);
			}
		} else if (temp < allowed_max_low) {
#ifdef CONFIG_SEC_DVFS
			if (cpufreq_get_dvfs_state() != 1) {
				if (cpu_policy->max
					< per_cpu(limits, cpu)) {
					max_freq = per_cpu(limits, cpu);
					update_policy = 1;
				}
			} else
				update_policy = 0;
#else
			if (cpu_policy->max < per_cpu(limits, cpu)) {
				max_freq = per_cpu(limits, cpu);
				update_policy = 1;
			} else {
				pr_debug("msm_thermal: policy max for cpu %d "
					 "already at max allowed\n", cpu);
			}
#endif
		}
		spin_unlock(&limits_lock);

		if (update_policy)
			update_cpu_max_freq(cpu_policy, cpu, max_freq);

		cpufreq_cpu_put(cpu_policy);
	}

reschedule:
	if (enabled)
		schedule_delayed_work(&check_temp_work,
				msecs_to_jiffies(check_interval_ms));
}

static void disable_msm_thermal(void)
{
	int cpu = 0;
	struct cpufreq_policy *cpu_policy = NULL;

	for_each_possible_cpu(cpu) {
		cpu_policy = cpufreq_cpu_get(cpu);
		if (cpu_policy) {
			if (cpu_policy->max < per_cpu(limits, cpu))
				update_cpu_max_freq(cpu_policy, cpu,
					per_cpu(limits, cpu));
			cpufreq_cpu_put(cpu_policy);
		}
	}
}

static int set_enabled(const char *val, const struct kernel_param *kp)
{
	int ret = 0;

	ret = param_set_bool(val, kp);
	if (!enabled)
		disable_msm_thermal();
	else
		pr_info("msm_thermal: no action for enabled = %d\n", enabled);

	pr_info("msm_thermal: enabled = %d\n", enabled);

	return ret;
}

static struct kernel_param_ops module_ops = {
	.set = set_enabled,
	.get = param_get_bool,
};

struct notifier_block limits_notify;

static int cpufreq_limits_handler(struct notifier_block *nb,
		unsigned long val, void *data) {
	/* user_policy generally isn't updated until after the notifier blocks
	 * get called, so .max != .user_policy.max here.  In the event that
	 * thermal throttling begins while SEC_DVFS has reduced the maximum
	 * frequency, the old user_policy value (the actual maximum) is lost.
	 *
	 * There's not a good way around this, but fortunately SEC_DVFS is
	 * never used to adjust the max.
	 */
	if (val == CPUFREQ_NOTIFY && spin_trylock(&limits_lock)) {
		struct cpufreq_policy *p = data;
		if (p->max <= MAX_FREQ_LIMIT &&
			p->max >= MIN_FREQ_LIMIT) {
			printk(KERN_DEBUG "msm_thermal: got new max %u\n",
				__func__, p->max);
			per_cpu(limits, p->cpu) = p->max;
		}
		spin_unlock(&limits_lock);
	}
	return 0;
}

module_param_cb(enabled, &module_ops, &enabled, 0644);
MODULE_PARM_DESC(enabled, "enforce thermal limit on cpu");

static int __init msm_thermal_init(void)
{
	int ret = 0;

	enabled = 1;
	INIT_DELAYED_WORK(&check_temp_work, check_temp);

	limits_notify.notifier_call = cpufreq_limits_handler;
	cpufreq_register_notifier(&limits_notify, CPUFREQ_POLICY_NOTIFIER);

	schedule_delayed_work(&check_temp_work, 0);

	return ret;
}
fs_initcall(msm_thermal_init);

