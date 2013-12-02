/*
 *  linux/drivers/cpufreq/cpufreq.c
 *
 *  Copyright (C) 2001 Russell King
 *            (C) 2002 - 2003 Dominik Brodowski <linux@brodo.de>
 *
 *  Oct 2005 - Ashok Raj <ashok.raj@intel.com>
 *	Added handling for CPU hotplug
 *  Feb 2006 - Jacob Shin <jacob.shin@amd.com>
 *	Fix handling for CPU hotplug -- affected CPUs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/syscore_ops.h>
#include <linux/sched.h>
#include <linux/gen_attr.h>
#include <linux/dkp.h>

#include <trace/events/power.h>
#include <linux/semaphore.h>

#if !defined(__MP_DECISION_PATCH__)
#error "__MP_DECISION_PATCH__ must be defined in cpufreq.c"
#endif
/* Description of __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
 *
 * When the kobject of cpufreq's ref count is zero in show/store function,
 * cpufreq_cpu_put() causes a deadlock because the active count of the
 * accessing file is incremented just before calling show/store at
 * fill_read(write)_buffer.
 * (This happens when show/store is called first and then the cpu_down is called
 * before the show/store function is finished)
 * So basically, cpufreq_cpu_put() in show/store must not release the kobject
 * of cpufreq. To make sure that kobj ref count of the cpufreq is not 0 in this
 * case, a per cpu mutex is used.
 * This per cpu mutex wraps the whole show/store function and kobject_put()
 * function in __cpufreq_remove_dev().
 */
 #define __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX


#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
static DEFINE_PER_CPU(struct mutex, cpufreq_remove_mutex);
#endif

/**
 * The "cpufreq driver" - the arch- or hardware-dependent low
 * level driver of CPUFreq support, and its spinlock. This lock
 * also protects the cpufreq_cpu_data array.
 */
static struct cpufreq_driver *cpufreq_driver;
static DEFINE_PER_CPU(struct cpufreq_policy *, cpufreq_cpu_data);
#ifdef CONFIG_HOTPLUG_CPU
/* This one keeps track of the previously set governor of a removed CPU */
struct cpufreq_cpu_save_data {
	char gov[CPUFREQ_NAME_LEN];
	unsigned int max, min;
};
static DEFINE_PER_CPU(struct cpufreq_cpu_save_data, cpufreq_policy_save);
#endif
static DEFINE_SPINLOCK(cpufreq_driver_lock);

/*
 * cpu_policy_rwsem is a per CPU reader-writer semaphore designed to cure
 * all cpufreq/hotplug/workqueue/etc related lock issues.
 *
 * The rules for this semaphore:
 * - Any routine that wants to read from the policy structure will
 *   do a down_read on this semaphore.
 * - Any routine that will write to the policy structure and/or may take away
 *   the policy altogether (eg. CPU hotplug), will hold this lock in write
 *   mode before doing so.
 *
 * Additional rules:
 * - All holders of the lock should check to make sure that the CPU they
 *   are concerned with are online after they get the lock.
 * - Governor routines that can be called in cpufreq hotplug path should not
 *   take this sem as top level hotplug notifier handler takes this.
 * - Lock should not be held across
 *     __cpufreq_governor(data, CPUFREQ_GOV_STOP);
 */
static DEFINE_PER_CPU(int, cpufreq_policy_cpu);
static DEFINE_PER_CPU(struct rw_semaphore, cpu_policy_rwsem);

#define lock_policy_rwsem(mode, cpu)					\
int lock_policy_rwsem_##mode						\
(int cpu)								\
{									\
	int policy_cpu = per_cpu(cpufreq_policy_cpu, cpu);		\
	BUG_ON(policy_cpu == -1);					\
	down_##mode(&per_cpu(cpu_policy_rwsem, policy_cpu));		\
	if (unlikely(!cpu_online(cpu))) {				\
		up_##mode(&per_cpu(cpu_policy_rwsem, policy_cpu));	\
		return -1;						\
	}								\
									\
	return 0;							\
}

lock_policy_rwsem(read, cpu);

lock_policy_rwsem(write, cpu);

static void unlock_policy_rwsem_read(int cpu)
{
	int policy_cpu = per_cpu(cpufreq_policy_cpu, cpu);
	BUG_ON(policy_cpu == -1);
	up_read(&per_cpu(cpu_policy_rwsem, policy_cpu));
}

void unlock_policy_rwsem_write(int cpu)
{
	int policy_cpu = per_cpu(cpufreq_policy_cpu, cpu);
	BUG_ON(policy_cpu == -1);
	up_write(&per_cpu(cpu_policy_rwsem, policy_cpu));
}


/* internal prototypes */
static int __cpufreq_governor(struct cpufreq_policy *policy,
		unsigned int event);
static unsigned int __cpufreq_get(unsigned int cpu);
static void handle_update(struct work_struct *work);

/**
 * Two notifier lists: the "policy" list is involved in the
 * validation process for a new CPU frequency policy; the
 * "transition" list for kernel code that needs to handle
 * changes to devices when the CPU clock speed changes.
 * The mutex locks both lists.
 */
static BLOCKING_NOTIFIER_HEAD(cpufreq_policy_notifier_list);
static struct srcu_notifier_head cpufreq_transition_notifier_list;

static bool init_cpufreq_transition_notifier_list_called;
static int __init init_cpufreq_transition_notifier_list(void)
{
	srcu_init_notifier_head(&cpufreq_transition_notifier_list);
	init_cpufreq_transition_notifier_list_called = true;
	return 0;
}
pure_initcall(init_cpufreq_transition_notifier_list);

static LIST_HEAD(cpufreq_governor_list);
static DEFINE_MUTEX(cpufreq_governor_mutex);

static struct cpufreq_policy *__cpufreq_cpu_get(unsigned int cpu, int sysfs)
{
	struct cpufreq_policy *data;
	unsigned long flags;

	if (cpu >= nr_cpu_ids)
		goto err_out;

	/* get the cpufreq driver */
	spin_lock_irqsave(&cpufreq_driver_lock, flags);

	if (!cpufreq_driver)
		goto err_out_unlock;

	if (!try_module_get(cpufreq_driver->owner))
		goto err_out_unlock;


	/* get the CPU */
	data = per_cpu(cpufreq_cpu_data, cpu);

	if (!data)
		goto err_out_put_module;

	if (!sysfs && !kobject_get(&data->kobj))
		goto err_out_put_module;

	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
	return data;

err_out_put_module:
	module_put(cpufreq_driver->owner);
err_out_unlock:
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
err_out:
	return NULL;
}

struct cpufreq_policy *cpufreq_cpu_get(unsigned int cpu)
{
	return __cpufreq_cpu_get(cpu, 0);
}
EXPORT_SYMBOL_GPL(cpufreq_cpu_get);

static struct cpufreq_policy *cpufreq_cpu_get_sysfs(unsigned int cpu)
{
	return __cpufreq_cpu_get(cpu, 1);
}

static void __cpufreq_cpu_put(struct cpufreq_policy *data, int sysfs)
{
	if (!sysfs)
		kobject_put(&data->kobj);
	module_put(cpufreq_driver->owner);
}

void cpufreq_cpu_put(struct cpufreq_policy *data)
{
	__cpufreq_cpu_put(data, 0);
}
EXPORT_SYMBOL_GPL(cpufreq_cpu_put);

static void cpufreq_cpu_put_sysfs(struct cpufreq_policy *data)
{
	__cpufreq_cpu_put(data, 1);
}

#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
/* just peek to see if the cpufreq policy is available.
 * The caller must hold cpufreq_driver_lock
 */
struct cpufreq_policy *cpufreq_cpu_peek(unsigned int cpu)
{
	struct cpufreq_policy *data;

	if (cpu >= nr_cpu_ids)
		return NULL;

	if (!cpufreq_driver)
		return NULL;

	/* get the CPU */
	data = per_cpu(cpufreq_cpu_data, cpu);

	return data;
}
#endif

/*********************************************************************
 *            EXTERNALLY AFFECTING FREQUENCY CHANGES                 *
 *********************************************************************/

/**
 * adjust_jiffies - adjust the system "loops_per_jiffy"
 *
 * This function alters the system "loops_per_jiffy" for the clock
 * speed change. Note that loops_per_jiffy cannot be updated on SMP
 * systems as each CPU might be scaled differently. So, use the arch
 * per-CPU loops_per_jiffy value wherever possible.
 */
#ifndef CONFIG_SMP
static unsigned long l_p_j_ref;
static unsigned int  l_p_j_ref_freq;

static void adjust_jiffies(unsigned long val, struct cpufreq_freqs *ci)
{
	if (ci->flags & CPUFREQ_CONST_LOOPS)
		return;

	if (!l_p_j_ref_freq) {
		l_p_j_ref = loops_per_jiffy;
		l_p_j_ref_freq = ci->old;
		pr_debug("saving %lu as reference value for loops_per_jiffy; "
			"freq is %u kHz\n", l_p_j_ref, l_p_j_ref_freq);
	}
	if ((val == CPUFREQ_PRECHANGE  && ci->old < ci->new) ||
	    (val == CPUFREQ_POSTCHANGE && ci->old > ci->new) ||
	    (val == CPUFREQ_RESUMECHANGE || val == CPUFREQ_SUSPENDCHANGE)) {
		loops_per_jiffy = cpufreq_scale(l_p_j_ref, l_p_j_ref_freq,
								ci->new);
		pr_debug("scaling loops_per_jiffy to %lu "
			"for frequency %u kHz\n", loops_per_jiffy, ci->new);
	}
}
#else
static inline void adjust_jiffies(unsigned long val, struct cpufreq_freqs *ci)
{
	return;
}
#endif


/**
 * cpufreq_notify_transition - call notifier chain and adjust_jiffies
 * on frequency transition.
 *
 * This function calls the transition notifiers and the "adjust_jiffies"
 * function. It is called twice on all CPU frequency changes that have
 * external effects.
 */
void cpufreq_notify_transition(struct cpufreq_freqs *freqs, unsigned int state)
{
	struct cpufreq_policy *policy;

	BUG_ON(irqs_disabled());

	freqs->flags = cpufreq_driver->flags;
	pr_debug("notification %u of frequency transition to %u kHz\n",
		state, freqs->new);

	policy = per_cpu(cpufreq_cpu_data, freqs->cpu);
	switch (state) {

	case CPUFREQ_PRECHANGE:
		/* detect if the driver reported a value as "old frequency"
		 * which is not equal to what the cpufreq core thinks is
		 * "old frequency".
		 */
		if (!(cpufreq_driver->flags & CPUFREQ_CONST_LOOPS)) {
			if ((policy) && (policy->cpu == freqs->cpu) &&
			    (policy->cur) && (policy->cur != freqs->old)) {
				pr_debug("Warning: CPU frequency is"
					" %u, cpufreq assumed %u kHz.\n",
					freqs->old, policy->cur);
				freqs->old = policy->cur;
			}
		}
		srcu_notifier_call_chain(&cpufreq_transition_notifier_list,
				CPUFREQ_PRECHANGE, freqs);
		adjust_jiffies(CPUFREQ_PRECHANGE, freqs);
		break;

	case CPUFREQ_POSTCHANGE:
		adjust_jiffies(CPUFREQ_POSTCHANGE, freqs);
		pr_debug("FREQ: %lu - CPU: %lu", (unsigned long)freqs->new,
			(unsigned long)freqs->cpu);
		trace_power_frequency(POWER_PSTATE, freqs->new, freqs->cpu);
		trace_cpu_frequency(freqs->new, freqs->cpu);
		srcu_notifier_call_chain(&cpufreq_transition_notifier_list,
				CPUFREQ_POSTCHANGE, freqs);
		if (likely(policy) && likely(policy->cpu == freqs->cpu))
			policy->cur = freqs->new;
		break;
	}
}
EXPORT_SYMBOL_GPL(cpufreq_notify_transition);

#if defined(__MP_DECISION_PATCH__)
/*
 * cpufreq_notify_utilization - notify CPU userspace abt CPU utilization
 * change
 *
 * This function calls the sysfs notifiers function.
 * It is called every ondemand load evaluation to compute CPU loading.
 */
void cpufreq_notify_utilization(struct cpufreq_policy *policy,
				unsigned int utils)
{
	if (policy)
		policy->utils = utils;

	sysfs_notify(&policy->kobj, NULL, "cpu_utilization");
}
#endif

/*********************************************************************
 *                          SYSFS INTERFACE                          *
 *********************************************************************/

static struct cpufreq_governor *__find_governor(const char *str_governor)
{
	struct cpufreq_governor *t;

	list_for_each_entry(t, &cpufreq_governor_list, governor_list)
		if (!strnicmp(str_governor, t->name, CPUFREQ_NAME_LEN))
			return t;

	return NULL;
}

/**
 * cpufreq_parse_governor - parse a governor string
 */
static int cpufreq_parse_governor(char *str_governor, unsigned int *policy,
				struct cpufreq_governor **governor)
{
	int err = -EINVAL;

	if (!cpufreq_driver)
		goto out;

	if (cpufreq_driver->setpolicy) {
		if (!strnicmp(str_governor, "performance", CPUFREQ_NAME_LEN)) {
			*policy = CPUFREQ_POLICY_PERFORMANCE;
			err = 0;
		} else if (!strnicmp(str_governor, "powersave",
						CPUFREQ_NAME_LEN)) {
			*policy = CPUFREQ_POLICY_POWERSAVE;
			err = 0;
		}
	} else if (cpufreq_driver->target) {
		struct cpufreq_governor *t;

		mutex_lock(&cpufreq_governor_mutex);

		t = __find_governor(str_governor);

		if (t == NULL) {
			int ret;

			mutex_unlock(&cpufreq_governor_mutex);
			ret = request_module("cpufreq_%s", str_governor);
			mutex_lock(&cpufreq_governor_mutex);

			if (ret == 0)
				t = __find_governor(str_governor);
		}

		if (t != NULL) {
			*governor = t;
			err = 0;
		}

		mutex_unlock(&cpufreq_governor_mutex);
	}
out:
	return err;
}


/**
 * cpufreq_per_cpu_attr_read() / show_##file_name() -
 * print out cpufreq information
 *
 * Write out information from cpufreq_driver->policy[cpu]; object must be
 * "unsigned int".
 */

#define show_one(file_name, object)			\
static ssize_t show_##file_name				\
(struct cpufreq_policy *policy, char *buf)		\
{							\
	return sprintf(buf, "%u\n", policy->object);	\
}

show_one(cpuinfo_min_freq, cpuinfo.min_freq);
show_one(cpuinfo_max_freq, cpuinfo.max_freq);
show_one(cpuinfo_transition_latency, cpuinfo.transition_latency);
show_one(scaling_min_freq, user_policy.min);
//show_one(scaling_max_freq, max);
show_one(scaling_cur_freq, cur);
#if defined(__MP_DECISION_PATCH__)
show_one(cpu_utilization, utils);
#endif

/* thermald watches scaling_max_freq and resets it to 1512 when it's changed.
 * We filter its input and output in order to keep it behaving.  Rather than
 * run a strcmp during every show/store, we cache its task_struct.
 */
static struct task_struct *thermald;
static int check_current_is_thermald(void) {
	int ret = 0;
	if (current != thermald) {
		if (!strcmp(current->comm, "thermald")) {
			printk(KERN_DEBUG "%s: found thermald (pid %u)!\n",
				__func__, current->pid);
			thermald = current;
			ret = 1;
		}
	} else {
		ret = 1;
	}
	return ret;
}

static ssize_t show_scaling_max_freq(struct cpufreq_policy *policy, char *buf)
{
	int val = 0;

	if (check_current_is_thermald() &&
		policy->max == policy->user_policy.max) {
			val = 1512000;
	} else {
		val = policy->user_policy.max;
	}
	return sprintf(buf, "%u\n", val);
}

static int __cpufreq_set_policy(struct cpufreq_policy *data,
				struct cpufreq_policy *policy);

/**
 * cpufreq_per_cpu_attr_write() / store_##file_name() - sysfs write access
 */
#define store_one(file_name, object)			\
static ssize_t store_##file_name					\
(struct cpufreq_policy *policy, const char *buf, size_t count)		\
{									\
	unsigned int ret = -EINVAL;					\
	struct cpufreq_policy new_policy;				\
									\
	ret = cpufreq_get_policy(&new_policy, policy->cpu);		\
	if (ret)							\
		return -EINVAL;						\
									\
	ret = sscanf(buf, "%u", &new_policy.object);			\
	if (ret != 1)							\
		return -EINVAL;						\
									\
	ret = __cpufreq_set_policy(policy, &new_policy);		\
	policy->user_policy.object = policy->object;			\
									\
	return ret ? ret : count;					\
}

static int dont_touch_my_shit = 0;
static __GATTR(dont_touch_my_shit, 0, 1, NULL);

#ifdef CONFIG_INTERACTION_HINTS
static bool handle_interaction = 0;
#endif

static ssize_t store_scaling_min_freq
(struct cpufreq_policy *policy, const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int value = 0;

	if (unlikely(dont_touch_my_shit)) {
		struct task_struct *t;
		printk(KERN_DEBUG "%s: setting %s, trace:\n", __func__, buf);
		for (t = current; t->real_parent && t->pid; t = t->real_parent)
			printk(KERN_DEBUG "%s: - %s\n", __func__, t->comm);
	}

	ret = sscanf(buf, "%u", &value);
	if (ret != 1)
		return -EINVAL;

#ifdef CONFIG_SEC_DVFS
	if (policy->cpu == BOOT_CPU) {
		if (value <= MIN_FREQ_LIMIT)
			cpufreq_set_limit_defered(USER_MIN_STOP, value);
		else if (value <= MAX_FREQ_LIMIT)
			cpufreq_set_limit_defered(USER_MIN_START, value);
	}

	return count;
#else
	printk(KERN_DEBUG "%s: queuing %u\n", __func__, value);
	cpufreq_queue_dvfs(QDVFS_USER | QDVFS_SET, value);
#endif
}

struct freq_work_struct {
	struct work_struct work;
	unsigned int freq;
	struct cpufreq_policy *policy;
};
void acpuclk_enable_oc_freqs(unsigned int freq);

static void do_enable_oc(struct work_struct *work) {
	int ret;
	unsigned int new_max = ((struct freq_work_struct *) work)->freq;
	struct cpufreq_policy new_policy;
	struct cpufreq_policy *policy =
		((struct freq_work_struct *) work)->policy;
	acpuclk_enable_oc_freqs(new_max);
	if (ret = cpufreq_get_policy(&new_policy, policy->cpu)) {
		printk(KERN_ERR "%s: can't get policy (%i)!\n", __func__, ret);
		goto out;
	}
	policy->cpuinfo.max_freq = new_policy.max = new_max;
	if (ret = __cpufreq_set_policy(policy, &new_policy)) {
		printk(KERN_ERR "%s: can't set policy (%i)!\n", __func__, ret);
		goto out;
	}
	policy->user_policy.max = policy->max;
out:
	kfree(work);
}

static ssize_t store_scaling_max_freq
	(struct cpufreq_policy *policy, const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int value = 0;
	bool is_thermald = 0;

	if (unlikely(dont_touch_my_shit)) {
		struct task_struct *t;
		printk(KERN_DEBUG "%s: setting %s, trace:\n", __func__, buf);
		for (t = current; t->real_parent && t->pid; t = t->real_parent)
			printk(KERN_DEBUG "%s: - %s\n", __func__, t->comm);
	}

	ret = sscanf(buf, "%u", &value);
	if (ret != 1)
		return -EINVAL;

	if (check_current_is_thermald()) {
		printk(KERN_DEBUG "%s: mangling thermald frequency %u\n", __func__, value);
		is_thermald = 1;
		if (value == 1512000)
			value = policy->user_policy.max;
	}

	if (value > BOOT_FREQ_LIMIT) {
		static struct freq_work_struct *enable_oc_work;
		enable_oc_work = kzalloc(sizeof(struct freq_work_struct), GFP_KERNEL);
		if (enable_oc_work) {
			INIT_WORK((struct work_struct *) enable_oc_work, do_enable_oc);
			enable_oc_work->freq = value;
			enable_oc_work->policy = policy;
			schedule_work((struct work_struct *) enable_oc_work);
		}
		return count;
	}

#ifdef CONFIG_SEC_DVFS
	if (policy->cpu == BOOT_CPU) {
		if (value >= MAX_FREQ_LIMIT)
			cpufreq_set_limit_defered(USER_MAX_STOP, value);
		else if (value >= MIN_FREQ_LIMIT)
			cpufreq_set_limit_defered(USER_MAX_START, value);
	}

	return count;
#else
	printk(KERN_DEBUG "%s: queuing %u\n", __func__, value);
	cpufreq_queue_dvfs(QDVFS_USER | QDVFS_MAX | QDVFS_SET, value);
#endif
}

/**
 * show_cpuinfo_cur_freq - current CPU frequency as detected by hardware
 */
static ssize_t show_cpuinfo_cur_freq(struct cpufreq_policy *policy,
					char *buf)
{
	unsigned int cur_freq = __cpufreq_get(policy->cpu);
	if (!cur_freq)
		return sprintf(buf, "<unknown>");
	return sprintf(buf, "%u\n", cur_freq);
}

/**
 * show_scaling_governor - show the current policy for the specified CPU
 */
static ssize_t show_scaling_governor(struct cpufreq_policy *policy, char *buf)
{
	if (policy->policy == CPUFREQ_POLICY_POWERSAVE)
		return sprintf(buf, "powersave\n");
	else if (policy->policy == CPUFREQ_POLICY_PERFORMANCE)
		return sprintf(buf, "performance\n");
	else if (policy->governor)
		return scnprintf(buf, CPUFREQ_NAME_LEN, "%s\n",
				policy->governor->name);
	return -EINVAL;
}

/**
 * auto-hotplug tuners, to be merged into governor settings as needed
 */
int hotplug_intpulse = 0;
int hotplug_sampling_periods = 15;
int hotplug_sampling_rate = 2000 / HZ;
int __used hotplug_enable_all_threshold = 1000;
int hotplug_enable_one_threshold = 250;
int hotplug_disable_one_threshold = 125;
static __GATTR(hotplug_intpulse, 0, 1, NULL);
static __GATTR(hotplug_sampling_periods, 2, 15, NULL);
static __GATTR(hotplug_sampling_rate, 1, 10, NULL);
//static __GATTR(hotplug_enable_all_threshold, 100, 1000, NULL);
static __GATTR(hotplug_enable_one_threshold, 100, 1000, NULL);
static __GATTR(hotplug_disable_one_threshold, 0, 1000, NULL);
static struct attribute *hotplug_attrs[] = {
	&gen_attr(hotplug_intpulse),
	&gen_attr(hotplug_sampling_periods),
	&gen_attr(hotplug_sampling_rate),
	//&gen_attr(hotplug_enable_all_threshold),
	&gen_attr(hotplug_enable_one_threshold),
	&gen_attr(hotplug_disable_one_threshold),
	NULL
};
static struct attribute_group hotplug_attr_grp = {
    .attrs = hotplug_attrs,
};

/**
 * store_scaling_governor - store policy for the specified CPU
 */
static ssize_t store_scaling_governor(struct cpufreq_policy *policy,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	char	str_governor[16];
	struct cpufreq_policy new_policy;
	bool need_hotplug = 0;

	ret = cpufreq_get_policy(&new_policy, policy->cpu);
	if (ret)
		return ret;

	ret = sscanf(buf, "%15s", str_governor);
	if (ret != 1)
		return -EINVAL;

	if (cpufreq_parse_governor(str_governor, &new_policy.policy,
						&new_policy.governor))
		return -EINVAL;

	if (!policy->cpu &&
	    policy->governor != new_policy.governor &&
	    !(new_policy.governor->flags & BIT(GOVFLAGS_HOTPLUG)))
		need_hotplug = 1;

	/* Do not use cpufreq_set_policy here or the user_policy.max
	   will be wrongly overridden */
	ret = __cpufreq_set_policy(policy, &new_policy);

	policy->user_policy.policy = policy->policy;
	policy->user_policy.governor = policy->governor;

	if (need_hotplug) {
		hotplug_attr_grp.name = policy->governor->name;
		sysfs_merge_group(cpufreq_global_kobject, &hotplug_attr_grp);
	}

#ifdef CONFIG_INTERACTION_HINTS
	handle_interaction = 1;
#endif

	if (ret)
		return ret;
	else
		return count;
}

/**
 * show_scaling_driver - show the cpufreq driver currently loaded
 */
static ssize_t show_scaling_driver(struct cpufreq_policy *policy, char *buf)
{
	return scnprintf(buf, CPUFREQ_NAME_LEN, "%s\n", cpufreq_driver->name);
}

/**
 * show_scaling_available_governors - show the available CPUfreq governors
 */
static ssize_t show_scaling_available_governors(struct cpufreq_policy *policy,
						char *buf)
{
	ssize_t i = 0;
	struct cpufreq_governor *t;

	if (!cpufreq_driver->target) {
		i += sprintf(buf, "performance powersave");
		goto out;
	}

	list_for_each_entry(t, &cpufreq_governor_list, governor_list) {
		if (i >= (ssize_t) ((PAGE_SIZE / sizeof(char))
		    - (CPUFREQ_NAME_LEN + 2)))
			goto out;
		i += scnprintf(&buf[i], CPUFREQ_NAME_LEN, "%s ", t->name);
	}
out:
	i += sprintf(&buf[i], "\n");
	return i;
}

static ssize_t show_cpus(const struct cpumask *mask, char *buf)
{
	ssize_t i = 0;
	unsigned int cpu;

	for_each_cpu(cpu, mask) {
		if (i)
			i += scnprintf(&buf[i], (PAGE_SIZE - i - 2), " ");
		i += scnprintf(&buf[i], (PAGE_SIZE - i - 2), "%u", cpu);
		if (i >= (PAGE_SIZE - 5))
			break;
	}
	i += sprintf(&buf[i], "\n");
	return i;
}

/**
 * show_related_cpus - show the CPUs affected by each transition even if
 * hw coordination is in use
 */
static ssize_t show_related_cpus(struct cpufreq_policy *policy, char *buf)
{
	if (cpumask_empty(policy->related_cpus))
		return show_cpus(policy->cpus, buf);
	return show_cpus(policy->related_cpus, buf);
}

/**
 * show_affected_cpus - show the CPUs affected by each transition
 */
static ssize_t show_affected_cpus(struct cpufreq_policy *policy, char *buf)
{
	return show_cpus(policy->cpus, buf);
}

static ssize_t store_scaling_setspeed(struct cpufreq_policy *policy,
					const char *buf, size_t count)
{
	unsigned int freq = 0;
	unsigned int ret;

	if (!policy->governor || !policy->governor->store_setspeed)
		return -EINVAL;

	ret = sscanf(buf, "%u", &freq);
	if (ret != 1)
		return -EINVAL;

	policy->governor->store_setspeed(policy, freq);

	return count;
}

static ssize_t show_scaling_setspeed(struct cpufreq_policy *policy, char *buf)
{
	if (!policy->governor || !policy->governor->show_setspeed)
		return sprintf(buf, "<unsupported>\n");

	return policy->governor->show_setspeed(policy, buf);
}

/* Per-core UV interface */
ssize_t acpuclk_store_vdd_table(const char *buf, size_t count);
ssize_t acpuclk_show_vdd_table(char *buf, char *fmt, int dir, int fdiv, int vdiv);
static ssize_t store_UV_mV_table(struct cpufreq_policy *policy,
					const char *buf, size_t count) {
	return acpuclk_store_vdd_table(buf, count);
}
static ssize_t show_UV_mV_table(struct cpufreq_policy *policy, char *buf) {
	return acpuclk_show_vdd_table(buf, "%umhz: %u mV\n", -1, 1000, 1000);
}

/* Control gov/min/max linking across cores */
static int link_core_settings = 1;
static __GATTR(link_core_settings, 0, 1, NULL);

/**
 * show_scaling_driver - show the current cpufreq HW/BIOS limitation
 */
static ssize_t show_bios_limit(struct cpufreq_policy *policy, char *buf)
{
	unsigned int limit;
	int ret;
	if (cpufreq_driver->bios_limit) {
		ret = cpufreq_driver->bios_limit(policy->cpu, &limit);
		if (!ret)
			return sprintf(buf, "%u\n", limit);
	}
	return sprintf(buf, "%u\n", policy->cpuinfo.max_freq);
}

cpufreq_freq_attr_ro_perm(cpuinfo_cur_freq, 0400);
cpufreq_freq_attr_ro(cpuinfo_min_freq);
cpufreq_freq_attr_ro(cpuinfo_max_freq);
cpufreq_freq_attr_ro(cpuinfo_transition_latency);
cpufreq_freq_attr_ro(scaling_available_governors);
cpufreq_freq_attr_ro(scaling_driver);
cpufreq_freq_attr_ro(scaling_cur_freq);
cpufreq_freq_attr_ro(bios_limit);
cpufreq_freq_attr_ro(related_cpus);
cpufreq_freq_attr_ro(affected_cpus);
#if defined(__MP_DECISION_PATCH__)
cpufreq_freq_attr_ro(cpu_utilization);
#endif
cpufreq_freq_attr_rw(scaling_min_freq);
cpufreq_freq_attr_rw(scaling_max_freq);
cpufreq_freq_attr_rw(scaling_governor);
cpufreq_freq_attr_rw(scaling_setspeed);
cpufreq_freq_attr_rw(UV_mV_table);

static struct attribute *default_attrs[] = {
	&cpuinfo_min_freq.attr,
	&cpuinfo_max_freq.attr,
	&cpuinfo_transition_latency.attr,
	&scaling_min_freq.attr,
	&scaling_max_freq.attr,
#if defined(__MP_DECISION_PATCH__)
	&cpu_utilization.attr,
#endif
	&affected_cpus.attr,
	&related_cpus.attr,
	&scaling_governor.attr,
	&scaling_driver.attr,
	&scaling_available_governors.attr,
	&scaling_setspeed.attr,
	&UV_mV_table.attr,
	NULL
};

struct kobject *cpufreq_global_kobject;
EXPORT_SYMBOL(cpufreq_global_kobject);

#define to_policy(k) container_of(k, struct cpufreq_policy, kobj)
#define to_attr(a) container_of(a, struct freq_attr, attr)

static ssize_t show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct cpufreq_policy *policy = to_policy(kobj);
	struct freq_attr *fattr = to_attr(attr);
	ssize_t ret = -EINVAL;
#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
	unsigned int cpu;
	unsigned long flags;
#endif

#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
	spin_lock_irqsave(&cpufreq_driver_lock, flags);
	policy = cpufreq_cpu_peek(policy->cpu);
	if (!policy) {
		spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
		return -EINVAL;
	}
	cpu = policy->cpu;
	if (mutex_trylock(&per_cpu(cpufreq_remove_mutex, cpu)) == 0) {
		spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
		pr_info("!WARN %s failed because cpu%u is going down\n",
			__func__, cpu);
		return -EINVAL;
	}
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
#endif
	policy = cpufreq_cpu_get_sysfs(policy->cpu);
	if (!policy)
		goto no_policy;

	if (lock_policy_rwsem_read(policy->cpu) < 0)
		goto fail;

	if (fattr->show)
		ret = fattr->show(policy, buf);
	else
		ret = -EIO;

	unlock_policy_rwsem_read(policy->cpu);
fail:
	cpufreq_cpu_put_sysfs(policy);
no_policy:
#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
	mutex_unlock(&per_cpu(cpufreq_remove_mutex, cpu));
#endif
	return ret;
}

extern void msm_rq_stats_enable(int enable);

static ssize_t store(struct kobject *kobj, struct attribute *attr,
		     const char *buf, size_t count)
{
        struct cpufreq_policy *policy = to_policy(kobj);
        struct freq_attr *fattr = to_attr(attr);
        ssize_t ret = count;

        int j, iter = 0, cpu = policy->cpu;

        /* This is a pain, but it's easier to handle shared settings here.  If
         * we're setting governor, we check flags and toggle mpdecision and
         * possibly assign to all cores.  If we're setting minimum or maxiumum
         * frequency, we assign to all cores.
         *
         * GOVFLAGS_ALLCPUS: all cpus must use this governor
         * GOVFLAGS_HOTPLUG: this governor hotplugs and doesn't need mpdecision
         */
	if (link_core_settings) {
		if (fattr->store == store_scaling_governor) {
			char name[16];
			unsigned int p = 0;
			struct cpufreq_governor *t = NULL;
			for (p = 0; p < 16; p++) {
				if (buf[p] == 0 || buf[p] == '\n')
					break;
				name[p] = buf[p];
			}
			name[p] = 0;
			cpufreq_parse_governor(name, &p, &t);
			if (!t)
				return -EINVAL;
			if (t->flags & BIT(GOVFLAGS_ALLCPUS)) {
				iter = 1;
			} else {
				// If cpu0 has ALLCPUS, they all do.
				if (per_cpu(cpufreq_cpu_data, 0)->governor->flags &
					BIT(GOVFLAGS_ALLCPUS)) {
					iter = 1;
				}
			}

			// If cpu0 can't enable cpu1, we need mpdecision
			if (cpu == 0)
				msm_rq_stats_enable(!(t->flags & BIT(GOVFLAGS_HOTPLUG)));
		} else if (fattr->store == store_scaling_max_freq ||
			   fattr->store == store_scaling_min_freq) {
			iter = 1;
		}
	}

        for_each_possible_cpu(j) {
                if (!iter && (j != cpu)) continue;
                /* Getting the policy the usual way here when it doesn't exist
                 * has unexpected consequences.  Check first.
                 */
                if (!per_cpu(cpufreq_cpu_data, j)) {
                        // store won't work, so adjust saved values
                        if (fattr->store == store_scaling_governor)
                                strncpy(per_cpu(cpufreq_policy_save, j).gov,
                                        buf, CPUFREQ_NAME_LEN);
                        else if (fattr->store == store_scaling_max_freq)
                                ret = sscanf(buf, "%u",
                                        &per_cpu(cpufreq_policy_save, j).max) ?
                                        ret : -EINVAL;
                        else if (fattr->store == store_scaling_min_freq)
                                ret = sscanf(buf, "%u",
                                        &per_cpu(cpufreq_policy_save, j).min) ?
                                        ret : -EINVAL;
                        continue;
                }

                // We have a policy, so it's safe to grab it.
                policy = cpufreq_cpu_get_sysfs(j);

                if (lock_policy_rwsem_write(j) < 0)
                        goto fail;

                if (fattr->store) {
                        int sr = fattr->store(policy, buf, count);
                        ret = sr < 0 ? sr : ret;
                } else
                        ret = -EIO;

                unlock_policy_rwsem_write(j);
fail:
                cpufreq_cpu_put_sysfs(policy);
        }

        return ret;
}

static void cpufreq_sysfs_release(struct kobject *kobj)
{
	struct cpufreq_policy *policy = to_policy(kobj);
	pr_debug("last reference is dropped\n");
	complete(&policy->kobj_unregister);
}

static const struct sysfs_ops sysfs_ops = {
	.show	= show,
	.store	= store,
};

static struct kobj_type ktype_cpufreq = {
	.sysfs_ops	= &sysfs_ops,
	.default_attrs	= default_attrs,
	.release	= cpufreq_sysfs_release,
};

/*
 * Returns:
 *   Negative: Failure
 *   0:        Success
 *   Positive: When we have a managed CPU and the sysfs got symlinked
 */
static int cpufreq_add_dev_policy(unsigned int cpu,
				  struct cpufreq_policy *policy,
				  struct sys_device *sys_dev)
{
	int ret = 0;
#ifdef CONFIG_SMP
	unsigned long flags;
	unsigned int j;
#ifdef CONFIG_HOTPLUG_CPU
	struct cpufreq_governor *gov;

	gov = __find_governor(per_cpu(cpufreq_policy_save, cpu).gov);
	if (gov) {
		policy->governor = gov;
		pr_debug("Restoring governor %s for cpu %d\n",
		       policy->governor->name, cpu);
	}
	if (per_cpu(cpufreq_policy_save, cpu).min) {
		policy->min = per_cpu(cpufreq_policy_save, cpu).min;
		policy->user_policy.min = policy->min;
	}
	if (per_cpu(cpufreq_policy_save, cpu).max) {
		policy->max = per_cpu(cpufreq_policy_save, cpu).max;
		policy->user_policy.max = policy->max;
	}
	pr_debug("Restoring CPU%d min %d and max %d\n",
		cpu, policy->min, policy->max);
#endif

	for_each_cpu(j, policy->cpus) {
		struct cpufreq_policy *managed_policy;

		if (cpu == j)
			continue;

		/* Check for existing affected CPUs.
		 * They may not be aware of it due to CPU Hotplug.
		 * cpufreq_cpu_put is called when the device is removed
		 * in __cpufreq_remove_dev()
		 */
		managed_policy = cpufreq_cpu_get(j);
		if (unlikely(managed_policy)) {

			/* Set proper policy_cpu */
			unlock_policy_rwsem_write(cpu);
			per_cpu(cpufreq_policy_cpu, cpu) = managed_policy->cpu;

			if (lock_policy_rwsem_write(cpu) < 0) {
				/* Should not go through policy unlock path */
				if (cpufreq_driver->exit)
					cpufreq_driver->exit(policy);
				cpufreq_cpu_put(managed_policy);
				return -EBUSY;
			}

			spin_lock_irqsave(&cpufreq_driver_lock, flags);
			cpumask_copy(managed_policy->cpus, policy->cpus);
			per_cpu(cpufreq_cpu_data, cpu) = managed_policy;
			spin_unlock_irqrestore(&cpufreq_driver_lock, flags);

			pr_debug("CPU already managed, adding link\n");
			ret = sysfs_create_link(&sys_dev->kobj,
						&managed_policy->kobj,
						"cpufreq");
			if (ret)
				cpufreq_cpu_put(managed_policy);
			/*
			 * Success. We only needed to be added to the mask.
			 * Call driver->exit() because only the cpu parent of
			 * the kobj needed to call init().
			 */
			if (cpufreq_driver->exit)
				cpufreq_driver->exit(policy);

			if (!ret)
				return 1;
			else
				return ret;
		}
	}
#endif
	return ret;
}


/* symlink affected CPUs */
static int cpufreq_add_dev_symlink(unsigned int cpu,
				   struct cpufreq_policy *policy)
{
	unsigned int j;
	int ret = 0;

	for_each_cpu(j, policy->cpus) {
		struct cpufreq_policy *managed_policy;
		struct sys_device *cpu_sys_dev;

		if (j == cpu)
			continue;
		if (!cpu_online(j))
			continue;

		pr_debug("CPU %u already managed, adding link\n", j);
		managed_policy = cpufreq_cpu_get(cpu);
		cpu_sys_dev = get_cpu_sysdev(j);
		ret = sysfs_create_link(&cpu_sys_dev->kobj, &policy->kobj,
					"cpufreq");
		if (ret) {
			cpufreq_cpu_put(managed_policy);
			return ret;
		}
	}
	return ret;
}

void acpuclk_maybe_add_override_vmin(struct kobject *kobj);
static int cpufreq_add_dev_interface(unsigned int cpu,
				     struct cpufreq_policy *policy,
				     struct sys_device *sys_dev)
{
	struct cpufreq_policy new_policy;
	struct freq_attr **drv_attr;
	unsigned long flags;
	int ret = 0;
	unsigned int j;

	/* prepare interface data */
	ret = kobject_init_and_add(&policy->kobj, &ktype_cpufreq,
				   &sys_dev->kobj, "cpufreq");
	if (ret)
		return ret;
	acpuclk_maybe_add_override_vmin(&policy->kobj);

	/* set up files for this cpu device */
	drv_attr = cpufreq_driver->attr;
	while ((drv_attr) && (*drv_attr)) {
		ret = sysfs_create_file(&policy->kobj, &((*drv_attr)->attr));
		if (ret)
			goto err_out_kobj_put;
		drv_attr++;
	}
	if (cpufreq_driver->get) {
		ret = sysfs_create_file(&policy->kobj, &cpuinfo_cur_freq.attr);
		if (ret)
			goto err_out_kobj_put;
	}
	if (cpufreq_driver->target) {
		ret = sysfs_create_file(&policy->kobj, &scaling_cur_freq.attr);
		if (ret)
			goto err_out_kobj_put;
	}
	if (cpufreq_driver->bios_limit) {
		ret = sysfs_create_file(&policy->kobj, &bios_limit.attr);
		if (ret)
			goto err_out_kobj_put;
	}

	spin_lock_irqsave(&cpufreq_driver_lock, flags);
	for_each_cpu(j, policy->cpus) {
		if (!cpu_online(j))
			continue;
		per_cpu(cpufreq_cpu_data, j) = policy;
		per_cpu(cpufreq_policy_cpu, j) = policy->cpu;
	}
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);

	ret = cpufreq_add_dev_symlink(cpu, policy);
	if (ret)
		goto err_out_kobj_put;

	memcpy(&new_policy, policy, sizeof(struct cpufreq_policy));
	/* assure that the starting sequence is run in __cpufreq_set_policy */
	policy->governor = NULL;

	/* set default policy */
	ret = __cpufreq_set_policy(policy, &new_policy);
	policy->user_policy.policy = policy->policy;
	policy->user_policy.governor = policy->governor;

	if (ret) {
		pr_debug("setting policy failed\n");
		if (cpufreq_driver->exit)
			cpufreq_driver->exit(policy);
	}
	return ret;

err_out_kobj_put:
	kobject_put(&policy->kobj);
	wait_for_completion(&policy->kobj_unregister);
	return ret;
}


/**
 * cpufreq_add_dev - add a CPU device
 *
 * Adds the cpufreq interface for a CPU device.
 *
 * The Oracle says: try running cpufreq registration/unregistration concurrently
 * with with cpu hotplugging and all hell will break loose. Tried to clean this
 * mess up, but more thorough testing is needed. - Mathieu
 */
static int cpufreq_add_dev(struct sys_device *sys_dev)
{
	unsigned int cpu = sys_dev->id;
	int ret = 0, found = 0;
	struct cpufreq_policy *policy;
	unsigned long flags;
	unsigned int j;
#ifdef CONFIG_HOTPLUG_CPU
	int sibling;
#endif

	if (cpu_is_offline(cpu))
		return 0;

	pr_debug("adding CPU %u\n", cpu);

#ifdef CONFIG_SMP
	/* check whether a different CPU already registered this
	 * CPU because it is in the same boat. */
	policy = cpufreq_cpu_get(cpu);
	if (unlikely(policy)) {
		cpufreq_cpu_put(policy);
		return 0;
	}
#endif

	if (!try_module_get(cpufreq_driver->owner)) {
		ret = -EINVAL;
		goto module_out;
	}

	ret = -ENOMEM;
	policy = kzalloc(sizeof(struct cpufreq_policy), GFP_KERNEL);
	if (!policy)
		goto nomem_out;

	if (!alloc_cpumask_var(&policy->cpus, GFP_KERNEL))
		goto err_free_policy;

	if (!zalloc_cpumask_var(&policy->related_cpus, GFP_KERNEL))
		goto err_free_cpumask;

	policy->cpu = cpu;
	cpumask_copy(policy->cpus, cpumask_of(cpu));

	/* Initially set CPU itself as the policy_cpu */
	per_cpu(cpufreq_policy_cpu, cpu) = cpu;
	ret = (lock_policy_rwsem_write(cpu) < 0);
	WARN_ON(ret);

	init_completion(&policy->kobj_unregister);
	INIT_WORK(&policy->update, handle_update);

	/* Set governor before ->init, so that driver could check it */
#ifdef CONFIG_HOTPLUG_CPU
	for_each_online_cpu(sibling) {
		struct cpufreq_policy *cp = per_cpu(cpufreq_cpu_data, sibling);
		if (cp && cp->governor &&
		    (cpumask_test_cpu(cpu, cp->related_cpus))) {
			policy->governor = cp->governor;
			found = 1;
			break;
		}
	}
#endif
	if (!found)
		policy->governor = CPUFREQ_DEFAULT_GOVERNOR;
	/* call driver. From then on the cpufreq must be able
	 * to accept all calls to ->verify and ->setpolicy for this CPU
	 */
	ret = cpufreq_driver->init(policy);
	if (ret) {
		pr_debug("initialization failed\n");
		goto err_unlock_policy;
	}
	policy->user_policy.min = policy->min;
	policy->user_policy.max = policy->max;

	blocking_notifier_call_chain(&cpufreq_policy_notifier_list,
				     CPUFREQ_START, policy);

	ret = cpufreq_add_dev_policy(cpu, policy, sys_dev);
	if (ret) {
		if (ret > 0)
			/* This is a managed cpu, symlink created,
			   exit with 0 */
			ret = 0;
		goto err_unlock_policy;
	}

	ret = cpufreq_add_dev_interface(cpu, policy, sys_dev);
	if (ret)
		goto err_out_unregister;

	unlock_policy_rwsem_write(cpu);

	kobject_uevent(&policy->kobj, KOBJ_ADD);
	module_put(cpufreq_driver->owner);
	pr_debug("initialization complete\n");

	return 0;


err_out_unregister:
	spin_lock_irqsave(&cpufreq_driver_lock, flags);
	for_each_cpu(j, policy->cpus)
		per_cpu(cpufreq_cpu_data, j) = NULL;
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);

	kobject_put(&policy->kobj);
	wait_for_completion(&policy->kobj_unregister);

err_unlock_policy:
	unlock_policy_rwsem_write(cpu);
	free_cpumask_var(policy->related_cpus);
err_free_cpumask:
	free_cpumask_var(policy->cpus);
err_free_policy:
	kfree(policy);
nomem_out:
	module_put(cpufreq_driver->owner);
module_out:
	return ret;
}


/**
 * __cpufreq_remove_dev - remove a CPU device
 *
 * Removes the cpufreq interface for a CPU device.
 * Caller should already have policy_rwsem in write mode for this CPU.
 * This routine frees the rwsem before returning.
 */
static int __cpufreq_remove_dev(struct sys_device *sys_dev)
{
	unsigned int cpu = sys_dev->id;
	unsigned long flags;
	struct cpufreq_policy *data;
	struct kobject *kobj;
	struct completion *cmp;
#ifdef CONFIG_SMP
	struct sys_device *cpu_sys_dev;
	unsigned int j;
#endif

	pr_debug("unregistering CPU %u\n", cpu);

	spin_lock_irqsave(&cpufreq_driver_lock, flags);
	data = per_cpu(cpufreq_cpu_data, cpu);

	if (!data) {
		spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
		unlock_policy_rwsem_write(cpu);
		return -EINVAL;
	}
	per_cpu(cpufreq_cpu_data, cpu) = NULL;


#ifdef CONFIG_SMP
	/* if this isn't the CPU which is the parent of the kobj, we
	 * only need to unlink, put and exit
	 */
	if (unlikely(cpu != data->cpu)) {
		pr_debug("removing link\n");
		cpumask_clear_cpu(cpu, data->cpus);
		spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
		kobj = &sys_dev->kobj;
		cpufreq_cpu_put(data);
		unlock_policy_rwsem_write(cpu);
		sysfs_remove_link(kobj, "cpufreq");
		return 0;
	}
#endif

#ifdef CONFIG_SMP

#ifdef CONFIG_HOTPLUG_CPU
	strncpy(per_cpu(cpufreq_policy_save, cpu).gov, data->governor->name,
			CPUFREQ_NAME_LEN);
	per_cpu(cpufreq_policy_save, cpu).min = data->user_policy.min;
	per_cpu(cpufreq_policy_save, cpu).max = data->user_policy.max;
	pr_debug("Saving CPU%d policy min %d and max %d\n",
			cpu, data->min, data->max);
#endif

	/* if we have other CPUs still registered, we need to unlink them,
	 * or else wait_for_completion below will lock up. Clean the
	 * per_cpu(cpufreq_cpu_data) while holding the lock, and remove
	 * the sysfs links afterwards.
	 */
	if (unlikely(cpumask_weight(data->cpus) > 1)) {
		for_each_cpu(j, data->cpus) {
			if (j == cpu)
				continue;
			per_cpu(cpufreq_cpu_data, j) = NULL;
		}
	}

	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);

	if (unlikely(cpumask_weight(data->cpus) > 1)) {
		for_each_cpu(j, data->cpus) {
			if (j == cpu)
				continue;
			pr_debug("removing link for cpu %u\n", j);
#ifdef CONFIG_HOTPLUG_CPU
			strncpy(per_cpu(cpufreq_policy_save, j).gov,
				data->governor->name, CPUFREQ_NAME_LEN);
			per_cpu(cpufreq_policy_save, j).min = data->user_policy.min;
			per_cpu(cpufreq_policy_save, j).max = data->user_policy.max;
			pr_debug("Saving CPU%d policy min %d and max %d\n",
					j, data->min, data->max);
#endif
			cpu_sys_dev = get_cpu_sysdev(j);
			kobj = &cpu_sys_dev->kobj;
			unlock_policy_rwsem_write(cpu);
			sysfs_remove_link(kobj, "cpufreq");
			lock_policy_rwsem_write(cpu);
			cpufreq_cpu_put(data);
		}
	}
#else
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
#endif

	if (cpufreq_driver->target)
		__cpufreq_governor(data, CPUFREQ_GOV_STOP);

	kobj = &data->kobj;
	cmp = &data->kobj_unregister;
	unlock_policy_rwsem_write(cpu);
#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
	mutex_lock(&per_cpu(cpufreq_remove_mutex, cpu));
#endif
	kobject_put(kobj);
#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
	mutex_unlock(&per_cpu(cpufreq_remove_mutex, cpu));
#endif
	/* we need to make sure that the underlying kobj is actually
	 * not referenced anymore by anybody before we proceed with
	 * unloading.
	 */
	pr_debug("waiting for dropping of refcount\n");
	wait_for_completion(cmp);
	pr_debug("wait complete\n");

	lock_policy_rwsem_write(cpu);
	if (cpufreq_driver->exit)
		cpufreq_driver->exit(data);
	unlock_policy_rwsem_write(cpu);

#ifdef CONFIG_HOTPLUG_CPU
	/* when the CPU which is the parent of the kobj is hotplugged
	 * offline, check for siblings, and create cpufreq sysfs interface
	 * and symlinks
	 */
	if (unlikely(cpumask_weight(data->cpus) > 1)) {
		/* first sibling now owns the new sysfs dir */
		cpumask_clear_cpu(cpu, data->cpus);
		cpufreq_add_dev(get_cpu_sysdev(cpumask_first(data->cpus)));

		/* finally remove our own symlink */
		lock_policy_rwsem_write(cpu);
		__cpufreq_remove_dev(sys_dev);
	}
#endif

	free_cpumask_var(data->related_cpus);
	free_cpumask_var(data->cpus);
	kfree(data);

	return 0;
}


static int cpufreq_remove_dev(struct sys_device *sys_dev)
{
	unsigned int cpu = sys_dev->id;
	int retval;

	if (cpu_is_offline(cpu))
		return 0;

	if (unlikely(lock_policy_rwsem_write(cpu)))
		BUG();

	retval = __cpufreq_remove_dev(sys_dev);
	return retval;
}


static void handle_update(struct work_struct *work)
{
	struct cpufreq_policy *policy =
		container_of(work, struct cpufreq_policy, update);
	unsigned int cpu = policy->cpu;
	pr_debug("handle_update for cpu %u called\n", cpu);
	cpufreq_update_policy(cpu);
}

/**
 *	cpufreq_out_of_sync - If actual and saved CPU frequency differs, we're in deep trouble.
 *	@cpu: cpu number
 *	@old_freq: CPU frequency the kernel thinks the CPU runs at
 *	@new_freq: CPU frequency the CPU actually runs at
 *
 *	We adjust to current frequency first, and need to clean up later.
 *	So either call to cpufreq_update_policy() or schedule handle_update()).
 */
static void cpufreq_out_of_sync(unsigned int cpu, unsigned int old_freq,
				unsigned int new_freq)
{
	struct cpufreq_freqs freqs;

	pr_debug("Warning: CPU frequency out of sync: cpufreq and timing "
	       "core thinks of %u, is %u kHz.\n", old_freq, new_freq);

	freqs.cpu = cpu;
	freqs.old = old_freq;
	freqs.new = new_freq;
	cpufreq_notify_transition(&freqs, CPUFREQ_PRECHANGE);
	cpufreq_notify_transition(&freqs, CPUFREQ_POSTCHANGE);
}


/**
 * cpufreq_quick_get - get the CPU frequency (in kHz) from policy->cur
 * @cpu: CPU number
 *
 * This is the last known freq, without actually getting it from the driver.
 * Return value will be same as what is shown in scaling_cur_freq in sysfs.
 */
unsigned int cpufreq_quick_get(unsigned int cpu)
{
	struct cpufreq_policy *policy = cpufreq_cpu_get(cpu);
	unsigned int ret_freq = 0;

	if (policy) {
		ret_freq = policy->cur;
		cpufreq_cpu_put(policy);
	}

	return ret_freq;
}
EXPORT_SYMBOL(cpufreq_quick_get);


static unsigned int __cpufreq_get(unsigned int cpu)
{
	struct cpufreq_policy *policy = per_cpu(cpufreq_cpu_data, cpu);
	unsigned int ret_freq = 0;

	if (!cpufreq_driver->get)
		return ret_freq;

	ret_freq = cpufreq_driver->get(cpu);

	if (ret_freq && policy->cur &&
		!(cpufreq_driver->flags & CPUFREQ_CONST_LOOPS)) {
		/* verify no discrepancy between actual and
					saved value exists */
		if (unlikely(ret_freq != policy->cur)) {
			cpufreq_out_of_sync(cpu, policy->cur, ret_freq);
			schedule_work(&policy->update);
		}
	}

	return ret_freq;
}

/**
 * cpufreq_get - get the current CPU frequency (in kHz)
 * @cpu: CPU number
 *
 * Get the CPU current (static) CPU frequency
 */
unsigned int cpufreq_get(unsigned int cpu)
{
	unsigned int ret_freq = 0;
	struct cpufreq_policy *policy = cpufreq_cpu_get(cpu);

	if (!policy)
		goto out;

	if (unlikely(lock_policy_rwsem_read(cpu)))
		goto out_policy;

	ret_freq = __cpufreq_get(cpu);

	unlock_policy_rwsem_read(cpu);

out_policy:
	cpufreq_cpu_put(policy);
out:
	return ret_freq;
}
EXPORT_SYMBOL(cpufreq_get);

static struct sysdev_driver cpufreq_sysdev_driver = {
	.add		= cpufreq_add_dev,
	.remove		= cpufreq_remove_dev,
};


/**
 * cpufreq_bp_suspend - Prepare the boot CPU for system suspend.
 *
 * This function is only executed for the boot processor.  The other CPUs
 * have been put offline by means of CPU hotplug.
 */
static int cpufreq_bp_suspend(void)
{
	int ret = 0;

	int cpu = smp_processor_id();
	struct cpufreq_policy *cpu_policy;

	pr_debug("suspending cpu %u\n", cpu);

	/* If there's no policy for the boot CPU, we have nothing to do. */
	cpu_policy = cpufreq_cpu_get(cpu);
	if (!cpu_policy)
		return 0;

	if (cpufreq_driver->suspend) {
		ret = cpufreq_driver->suspend(cpu_policy);
		if (ret)
			printk(KERN_ERR "cpufreq: suspend failed in ->suspend "
					"step on CPU %u\n", cpu_policy->cpu);
	}

	cpufreq_cpu_put(cpu_policy);
	return ret;
}

/**
 * cpufreq_bp_resume - Restore proper frequency handling of the boot CPU.
 *
 *	1.) resume CPUfreq hardware support (cpufreq_driver->resume())
 *	2.) schedule call cpufreq_update_policy() ASAP as interrupts are
 *	    restored. It will verify that the current freq is in sync with
 *	    what we believe it to be. This is a bit later than when it
 *	    should be, but nonethteless it's better than calling
 *	    cpufreq_driver->get() here which might re-enable interrupts...
 *
 * This function is only executed for the boot CPU.  The other CPUs have not
 * been turned on yet.
 */
static void cpufreq_bp_resume(void)
{
	int ret = 0;

	int cpu = smp_processor_id();
	struct cpufreq_policy *cpu_policy;

	pr_debug("resuming cpu %u\n", cpu);

	/* If there's no policy for the boot CPU, we have nothing to do. */
	cpu_policy = cpufreq_cpu_get(cpu);
	if (!cpu_policy)
		return;

	if (cpufreq_driver->resume) {
		ret = cpufreq_driver->resume(cpu_policy);
		if (ret) {
			printk(KERN_ERR "cpufreq: resume failed in ->resume "
					"step on CPU %u\n", cpu_policy->cpu);
			goto fail;
		}
	}

	schedule_work(&cpu_policy->update);

fail:
	cpufreq_cpu_put(cpu_policy);
}

static struct syscore_ops cpufreq_syscore_ops = {
	.suspend	= cpufreq_bp_suspend,
	.resume		= cpufreq_bp_resume,
};


/*********************************************************************
 *                     NOTIFIER LISTS INTERFACE                      *
 *********************************************************************/

/**
 *	cpufreq_register_notifier - register a driver with cpufreq
 *	@nb: notifier function to register
 *      @list: CPUFREQ_TRANSITION_NOTIFIER or CPUFREQ_POLICY_NOTIFIER
 *
 *	Add a driver to one of two lists: either a list of drivers that
 *      are notified about clock rate changes (once before and once after
 *      the transition), or a list of drivers that are notified about
 *      changes in cpufreq policy.
 *
 *	This function may sleep, and has the same return conditions as
 *	blocking_notifier_chain_register.
 */
int cpufreq_register_notifier(struct notifier_block *nb, unsigned int list)
{
	int ret;

	WARN_ON(!init_cpufreq_transition_notifier_list_called);

	switch (list) {
	case CPUFREQ_TRANSITION_NOTIFIER:
		ret = srcu_notifier_chain_register(
				&cpufreq_transition_notifier_list, nb);
		break;
	case CPUFREQ_POLICY_NOTIFIER:
		ret = blocking_notifier_chain_register(
				&cpufreq_policy_notifier_list, nb);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}
EXPORT_SYMBOL(cpufreq_register_notifier);


/**
 *	cpufreq_unregister_notifier - unregister a driver with cpufreq
 *	@nb: notifier block to be unregistered
 *      @list: CPUFREQ_TRANSITION_NOTIFIER or CPUFREQ_POLICY_NOTIFIER
 *
 *	Remove a driver from the CPU frequency notifier list.
 *
 *	This function may sleep, and has the same return conditions as
 *	blocking_notifier_chain_unregister.
 */
int cpufreq_unregister_notifier(struct notifier_block *nb, unsigned int list)
{
	int ret;

	switch (list) {
	case CPUFREQ_TRANSITION_NOTIFIER:
		ret = srcu_notifier_chain_unregister(
				&cpufreq_transition_notifier_list, nb);
		break;
	case CPUFREQ_POLICY_NOTIFIER:
		ret = blocking_notifier_chain_unregister(
				&cpufreq_policy_notifier_list, nb);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}
EXPORT_SYMBOL(cpufreq_unregister_notifier);


/*********************************************************************
 *                              GOVERNORS                            *
 *********************************************************************/


int __cpufreq_driver_target(struct cpufreq_policy *policy,
			    unsigned int target_freq,
			    unsigned int relation)
{
	int retval = -EINVAL;

	pr_debug("target for CPU %u: %u kHz, relation %u\n", policy->cpu,
		target_freq, relation);
	if (cpu_online(policy->cpu) && cpufreq_driver->target)
		retval = cpufreq_driver->target(policy, target_freq, relation);

	return retval;
}
EXPORT_SYMBOL_GPL(__cpufreq_driver_target);

int cpufreq_driver_target(struct cpufreq_policy *policy,
			  unsigned int target_freq,
			  unsigned int relation)
{
	int ret = -EINVAL;

	policy = cpufreq_cpu_get(policy->cpu);
	if (!policy)
		goto no_policy;

	if (unlikely(lock_policy_rwsem_write(policy->cpu)))
		goto fail;

	ret = __cpufreq_driver_target(policy, target_freq, relation);

	unlock_policy_rwsem_write(policy->cpu);

fail:
	cpufreq_cpu_put(policy);
no_policy:
	return ret;
}
EXPORT_SYMBOL_GPL(cpufreq_driver_target);

int __cpufreq_driver_getavg(struct cpufreq_policy *policy, unsigned int cpu)
{
	int ret = 0;

	policy = cpufreq_cpu_get(policy->cpu);
	if (!policy)
		return -EINVAL;

	if (cpu_online(cpu) && cpufreq_driver->getavg)
		ret = cpufreq_driver->getavg(policy, cpu);

	cpufreq_cpu_put(policy);
	return ret;
}
EXPORT_SYMBOL_GPL(__cpufreq_driver_getavg);

/*
 * when "event" is CPUFREQ_GOV_LIMITS
 */

static int __cpufreq_governor(struct cpufreq_policy *policy,
					unsigned int event)
{
	int ret;

	/* Only must be defined when default governor is known to have latency
	   restrictions, like e.g. conservative or ondemand.
	   That this is the case is already ensured in Kconfig
	*/
#ifdef CONFIG_CPU_FREQ_GOV_PERFORMANCE
	struct cpufreq_governor *gov = &cpufreq_gov_performance;
#else
	struct cpufreq_governor *gov = NULL;
#endif

	if (policy->governor->max_transition_latency &&
	    policy->cpuinfo.transition_latency >
	    policy->governor->max_transition_latency) {
		if (!gov)
			return -EINVAL;
		else {
			printk(KERN_WARNING "%s governor failed, too long"
			       " transition latency of HW, fallback"
			       " to %s governor\n",
			       policy->governor->name,
			       gov->name);
			policy->governor = gov;
		}
	}

	if (!try_module_get(policy->governor->owner))
		return -EINVAL;

	pr_debug("__cpufreq_governor for CPU %u, event %u\n",
						policy->cpu, event);
	ret = policy->governor->governor(policy, event);

	/* we keep one module reference alive for
			each CPU governed by this CPU */
	if ((event != CPUFREQ_GOV_START) || ret)
		module_put(policy->governor->owner);
	if ((event == CPUFREQ_GOV_STOP) && !ret)
		module_put(policy->governor->owner);

	return ret;
}


int cpufreq_register_governor(struct cpufreq_governor *governor)
{
	int err;

	if (!governor)
		return -EINVAL;

	mutex_lock(&cpufreq_governor_mutex);

	err = -EBUSY;
	if (__find_governor(governor->name) == NULL) {
		err = 0;
		list_add(&governor->governor_list, &cpufreq_governor_list);
	}

	mutex_unlock(&cpufreq_governor_mutex);
	return err;
}
EXPORT_SYMBOL_GPL(cpufreq_register_governor);


void cpufreq_unregister_governor(struct cpufreq_governor *governor)
{
#ifdef CONFIG_HOTPLUG_CPU
	int cpu;
#endif

	if (!governor)
		return;

#ifdef CONFIG_HOTPLUG_CPU
	for_each_present_cpu(cpu) {
		if (cpu_online(cpu))
			continue;
		if (!strcmp(per_cpu(cpufreq_policy_save, cpu).gov,
					governor->name))
			strcpy(per_cpu(cpufreq_policy_save, cpu).gov, "\0");
		per_cpu(cpufreq_policy_save, cpu).min = 0;
		per_cpu(cpufreq_policy_save, cpu).max = 0;
	}
#endif

	mutex_lock(&cpufreq_governor_mutex);
	list_del(&governor->governor_list);
	mutex_unlock(&cpufreq_governor_mutex);
	return;
}
EXPORT_SYMBOL_GPL(cpufreq_unregister_governor);



/*********************************************************************
 *                          POLICY INTERFACE                         *
 *********************************************************************/

/**
 * cpufreq_get_policy - get the current cpufreq_policy
 * @policy: struct cpufreq_policy into which the current cpufreq_policy
 *	is written
 *
 * Reads the current cpufreq policy.
 */
int cpufreq_get_policy(struct cpufreq_policy *policy, unsigned int cpu)
{
	struct cpufreq_policy *cpu_policy;
	if (!policy)
		return -EINVAL;

	cpu_policy = cpufreq_cpu_get(cpu);
	if (!cpu_policy)
		return -EINVAL;

	memcpy(policy, cpu_policy, sizeof(struct cpufreq_policy));

	cpufreq_cpu_put(cpu_policy);
	return 0;
}
EXPORT_SYMBOL(cpufreq_get_policy);


/*
 * data   : current policy.
 * policy : policy to be set.
 */
static int __cpufreq_set_policy(struct cpufreq_policy *data,
				struct cpufreq_policy *policy)
{
	int ret = 0;

	pr_debug("setting new policy for CPU %u: %u - %u kHz\n", policy->cpu,
		policy->min, policy->max);

	memcpy(&policy->cpuinfo, &data->cpuinfo,
				sizeof(struct cpufreq_cpuinfo));

	if (policy->min > data->max || policy->max < data->min) {
		ret = -EINVAL;
		goto error_out;
	}

	/* verify the cpu speed can be set within this limit */
	ret = cpufreq_driver->verify(policy);
	if (ret)
		goto error_out;

	/* adjust if necessary - all reasons */
	blocking_notifier_call_chain(&cpufreq_policy_notifier_list,
			CPUFREQ_ADJUST, policy);

	/* adjust if necessary - hardware incompatibility*/
	blocking_notifier_call_chain(&cpufreq_policy_notifier_list,
			CPUFREQ_INCOMPATIBLE, policy);

	/* verify the cpu speed can be set within this limit,
	   which might be different to the first one */
	ret = cpufreq_driver->verify(policy);
	if (ret)
		goto error_out;

	/* notification of the new policy */
	blocking_notifier_call_chain(&cpufreq_policy_notifier_list,
			CPUFREQ_NOTIFY, policy);

	data->min = policy->min;
	data->max = policy->max;

	pr_debug("new min and max freqs are %u - %u kHz\n",
					data->min, data->max);

	if (cpufreq_driver->setpolicy) {
		data->policy = policy->policy;
		pr_debug("setting range\n");
		ret = cpufreq_driver->setpolicy(policy);
	} else {
		if (policy->governor != data->governor) {
			/* save old, working values */
			struct cpufreq_governor *old_gov = data->governor;

			pr_debug("governor switch\n");

			/* end old governor */
			if (data->governor)
				__cpufreq_governor(data, CPUFREQ_GOV_STOP);

			/* start new governor */
			data->governor = policy->governor;
			if (__cpufreq_governor(data, CPUFREQ_GOV_START)) {
				/* new governor failed, so re-start old one */
				pr_debug("starting governor %s failed\n",
							data->governor->name);
				if (old_gov) {
					data->governor = old_gov;
					__cpufreq_governor(data,
							   CPUFREQ_GOV_START);
				}
				ret = -EINVAL;
				goto error_out;
			}
			/* might be a policy change, too, so fall through */
		}
		pr_debug("governor: change or update limits\n");
		__cpufreq_governor(data, CPUFREQ_GOV_LIMITS);
	}

error_out:
	return ret;
}

#ifdef CONFIG_INTERACTION_HINTS
static atomic_t interactivity_state;

static void do_interactivity(struct work_struct *work);
static DECLARE_WORK(interactivity_on_work, do_interactivity);
static DECLARE_WORK(interactivity_off_work, do_interactivity);

static void do_interactivity(struct work_struct *work) {
	unsigned int j;

	/* On TW, interactivity gets bumped during early boot, and trying to
	 * lock the rwsems deadlocks.  Bail out early if the governor hasn't
	 * been changed yet (i.e. init.qcom.post_boot.sh hasn't run).
	 */
	if (unlikely(!handle_interaction))
		return;

	for_each_online_cpu(j) {
		struct cpufreq_policy *pol;
		if (lock_policy_rwsem_read(j))
			continue;
		pol = per_cpu(cpufreq_cpu_data, j);
		if (unlikely(pol == NULL)) {
			printk(KERN_DEBUG "%s: policy for cpu %u is null\n", __func__, j);
		} else {
			pol->governor->governor(pol,
				work == &interactivity_on_work ?
				CPUFREQ_GOV_INTERACT : CPUFREQ_GOV_NOINTERACT);
		}
		unlock_policy_rwsem_read(j);
	}
}

void cpufreq_set_interactivity(int on, int idbit) {
	unsigned int mask = 1 << idbit;
	int old, new;
	{
	register unsigned long tmp;
	__asm__ __volatile__(
"1:	ldrex	%0, [%4]\n"
"	mov	%1, %0\n"
"	teq	%5, #0\n"
"	orrne	%0, %6\n"
"	biceq	%0, %6\n"
"	strex	%2, %0, [%4]\n"
"	teq	%2, #0\n"
"	bne	1b"
	: "=&r" (new), "=&r" (old), "=&r" (tmp), "+Qo" (interactivity_state.counter)
	: "r" (&interactivity_state.counter), "lr" (on), "lr" (mask)
	: "cc");
	}

	if (!old && new) {
		schedule_work(&interactivity_on_work);
	} else if (old && !new) {
		schedule_work(&interactivity_off_work);
	}
}
#endif

#ifdef CONFIG_SEC_DVFS
struct cpufreq_queue_data {
	unsigned int flag;
	unsigned int value;

	struct work_struct work;
	struct workqueue_struct *wq;
};

struct cpufreq_queue_data cpufreq_queue_priv;
static DEFINE_SEMAPHORE(cpufreq_defered_lock);
static DEFINE_MUTEX(set_cpu_freq_lock);

static unsigned long freq_limit_start_flag;
static unsigned int app_min_freq_limit = MIN_FREQ_LIMIT;
static unsigned int app_max_freq_limit = MAX_FREQ_LIMIT;
static unsigned int user_min_freq_limit = MIN_FREQ_LIMIT;
static unsigned int user_max_freq_limit = MAX_FREQ_LIMIT;

static int cpufreq_set_limits_off
	(int cpu, unsigned int min, unsigned int max)
{
	int ret = -ENODEV;
	unsigned long flags;

	spin_lock_irqsave(&cpufreq_driver_lock, flags);

	if (!cpufreq_driver)
		goto out_unlock;

	if (!try_module_get(cpufreq_driver->owner))
		goto out_unlock;

	per_cpu(cpufreq_policy_save, cpu).min = min;
	per_cpu(cpufreq_policy_save, cpu).max = max;

	ret = 0;

	module_put(cpufreq_driver->owner);

out_unlock:
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);

	return ret;
}

static int cpufreq_set_limits(int cpu, unsigned int min, unsigned int max,
	bool update_user)
{
	struct cpufreq_policy *policy = NULL;
	struct cpufreq_policy new_policy;
	int ret = -EINVAL;

	if (cpu_is_offline(cpu))
		goto no_policy;

	policy = cpufreq_cpu_get(cpu);
	if (!policy)
		goto no_policy;

	if (policy->min == min && policy->max == max)
		goto cpu_put;

	if (lock_policy_rwsem_write(cpu) < 0)
		goto cpu_put;

	ret = cpufreq_get_policy(&new_policy, policy->cpu);
	if (ret)
		goto unlock;

	if (max < policy->min) {
		new_policy.min = max;
		ret = __cpufreq_set_policy(policy, &new_policy);
	}

	if (min > policy->max) {
		new_policy.max = min;
		ret = __cpufreq_set_policy(policy, &new_policy);
	}

	new_policy.min = min;
	new_policy.max = max;

	ret = __cpufreq_set_policy(policy, &new_policy);

	if (update_user) {
		policy->user_policy.min = policy->min;
		policy->user_policy.max = policy->max;
	}

unlock:
	unlock_policy_rwsem_write(policy->cpu);

cpu_put:
	cpufreq_cpu_put(policy);

no_policy:
	if (cpu_is_offline(cpu))
		ret = cpufreq_set_limits_off(cpu, min, max);

	return ret;
}

int cpufreq_set_limit(unsigned int flag, unsigned int value)
{
	unsigned int max_value = 0;
	unsigned int min_value = 0;
	bool update_user = false;

	if (!flag) {
		printk(KERN_ERR"%s: invalid flag %d\n",
			__func__, flag);
		return -EINVAL;
	}

	mutex_lock(&set_cpu_freq_lock);

	/* update min/max freq limit for apps/user */
	if (flag == APPS_MAX_START)
		app_max_freq_limit = value;
	else if (flag == APPS_MAX_STOP)
		app_max_freq_limit = MAX_FREQ_LIMIT;
	else if (flag == APPS_MIN_START)
		app_min_freq_limit = value;
	else if (flag == APPS_MIN_STOP)
		app_min_freq_limit = MIN_FREQ_LIMIT;
	else if (flag == USER_MAX_START) {
		user_max_freq_limit = value;
		update_user = true;
	} else if (flag == USER_MAX_STOP) {
		user_max_freq_limit = value;
		update_user = true;
	} else if (flag == USER_MIN_START) {
		user_min_freq_limit = value;
		update_user = true;
	} else if (flag == USER_MIN_STOP) {
		user_min_freq_limit = value;
		update_user = true;
	}

	/*  set/clear bits */
	if (flag%10 == 0)
		set_bit(flag/MULTI_FACTOR, &freq_limit_start_flag);
	else
		clear_bit(flag/MULTI_FACTOR, &freq_limit_start_flag);

	if (flag == APPS_MIN_START && value == MAX_FREQ_LIMIT)
		clear_bit(UNI_PRO_STOP/MULTI_FACTOR, &freq_limit_start_flag);

	/* set max freq */
	if (freq_limit_start_flag & UNI_PRO_BIT)
		max_value = LOW_MAX_FREQ_LIMIT;
	else
		max_value = MAX_FREQ_LIMIT;

	/* cpufreq_max_limit */
	if (freq_limit_start_flag & APPS_MAX_BIT) {
		if (max_value > app_max_freq_limit)
			max_value = app_max_freq_limit;
	}

	/* thermald */
	if (freq_limit_start_flag & USER_MAX_BIT) {
		if (max_value > user_max_freq_limit)
			max_value = user_max_freq_limit;
	}

	/* set min freq */
	if (freq_limit_start_flag & TOUCH_BOOSTER_FIRST_BIT)
		min_value = TOUCH_BOOSTER_FIRST_FREQ_LIMIT;
	else if (freq_limit_start_flag & TOUCH_BOOSTER_SECOND_BIT)
		min_value = TOUCH_BOOSTER_SECOND_FREQ_LIMIT;
	else if (freq_limit_start_flag & TOUCH_BOOSTER_BIT)
		min_value = TOUCH_BOOSTER_FREQ_LIMIT;
	else
		min_value = MIN_FREQ_LIMIT;

	/* cpufreq_min_limit */
	if (freq_limit_start_flag & APPS_MIN_BIT) {
		if (min_value < app_min_freq_limit)
			min_value = app_min_freq_limit;
	}

	/* user */
	if (freq_limit_start_flag & USER_MIN_BIT) {
		if (min_value < user_min_freq_limit)
			min_value = user_min_freq_limit;
	}

	/* max is important */
	if (min_value > max_value)
		min_value = max_value;

	mutex_unlock(&set_cpu_freq_lock);

	/* update min/max */
	cpufreq_set_limits(BOOT_CPU, min_value, max_value, update_user);
	cpufreq_set_limits(NON_BOOT_CPU, min_value, max_value, update_user);

	return 0;
}

static void cpufreq_set_limit_work(struct work_struct *ws)
{
	struct cpufreq_queue_data *cq = NULL;

	if (ws) {
		cq = container_of(ws, struct cpufreq_queue_data, work);
		if (cq)
			cpufreq_set_limit(cq->flag, cq->value);
	}

	up(&cpufreq_defered_lock);
}

int cpufreq_set_limit_defered(unsigned int flag, unsigned value)
{
	int ret = 0;

	if (down_trylock(&cpufreq_defered_lock) == 0) {
		cpufreq_queue_priv.flag = flag;
		cpufreq_queue_priv.value = value;
		ret = queue_work_on(0, cpufreq_queue_priv.wq,
			&cpufreq_queue_priv.work);
		if (!ret)
			up(&cpufreq_defered_lock);
	} else
		ret = -EBUSY;

	return ret;
}
#else
// serializing allows us to make a few assumptions
static DEFINE_MUTEX(qdvfs_lock);
struct qdvfs_work {
	struct work_struct work;
	unsigned int value;
	char flag;
};
void do_queued_dvfs(struct work_struct *work) {
	struct qdvfs_work *q = work;
	int i;
	mutex_lock(&qdvfs_lock);
	printk(KERN_DEBUG "%s: %s %s %s (%u)\n", __func__,
		q->flag & QDVFS_SET ? "set" : "release",
		q->flag & QDVFS_USER ? "user" : "apps",
		q->flag & QDVFS_MAX ? "max" : "min",
		q->value);
	for_each_online_cpu(i) {
		struct cpufreq_policy new;
		struct cpufreq_policy *pol;
		unsigned int *active;
		unsigned int *user;

		pol = cpufreq_cpu_get(i);
		if (unlikely(!pol))
			continue;
		memcpy(&new, pol, sizeof(struct cpufreq_policy));

		// ...eww.
		active = q->flag & QDVFS_MAX ?
			&new.max : &new.min;
		user = q->flag & QDVFS_MAX ?
			&new.user_policy.max : &new.user_policy.min;
		if (q->flag & QDVFS_SET) {
			if (q->flag & QDVFS_USER) {
				if (*user == *active == q->value)
					goto out;
			} else {
				if (q->flag & QDVFS_MAX) {
					if (q->value > *user)
						q->value = *user;
				} else {
					if (q->value < *user)
						q->value = *user;
				}
				if (*active == q->value)
					goto out;
			}
			*active = q->value;
		} else {
			if (active == *user)
				goto out;
			*active = *user;
		}
		__cpufreq_set_policy(pol, &new);
		if (q->flag & QDVFS_USER) {
			user = q->flag & QDVFS_MAX ?
				&pol->user_policy.max : &pol->user_policy.min;
			*user = q->value;
		}
out:
		cpufreq_cpu_put(pol);
	}
	mutex_unlock(&qdvfs_lock);
	kfree(q);
}

void cpufreq_queue_dvfs(char flag, unsigned int value) {
	struct qdvfs_work *q = kmalloc(sizeof(struct qdvfs_work), GFP_KERNEL);
	if (!q)
		return;
	INIT_WORK(&q->work, do_queued_dvfs);
	q->value = value;
	q->flag = flag;
	schedule_work(&q->work);
}
#endif

/**
 *	cpufreq_update_policy - re-evaluate an existing cpufreq policy
 *	@cpu: CPU which shall be re-evaluated
 *
 *	Useful for policy notifiers which have different necessities
 *	at different times.
 */
int cpufreq_update_policy(unsigned int cpu)
{
	struct cpufreq_policy *data = cpufreq_cpu_get(cpu);
	struct cpufreq_policy policy;
	int ret;

	if (!data) {
		ret = -ENODEV;
		goto no_policy;
	}

	if (unlikely(lock_policy_rwsem_write(cpu))) {
		ret = -EINVAL;
		goto fail;
	}

	pr_debug("updating policy for CPU %u\n", cpu);
	memcpy(&policy, data, sizeof(struct cpufreq_policy));
	policy.min = data->user_policy.min;
	policy.max = data->user_policy.max;
	policy.policy = data->user_policy.policy;
	policy.governor = data->user_policy.governor;

	/* BIOS might change freq behind our back
	  -> ask driver for current freq and notify governors about a change */
	if (cpufreq_driver->get) {
		policy.cur = cpufreq_driver->get(cpu);
		if (!data->cur) {
			pr_debug("Driver did not initialize current freq");
			data->cur = policy.cur;
		} else {
			if (data->cur != policy.cur)
				cpufreq_out_of_sync(cpu, data->cur,
								policy.cur);
		}
	}

	ret = __cpufreq_set_policy(data, &policy);

	unlock_policy_rwsem_write(cpu);

fail:
	cpufreq_cpu_put(data);
no_policy:
	return ret;
}
EXPORT_SYMBOL(cpufreq_update_policy);

static int __cpuinit cpufreq_cpu_callback(struct notifier_block *nfb,
					unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;
	struct sys_device *sys_dev;

	sys_dev = get_cpu_sysdev(cpu);
	if (sys_dev) {
		switch (action) {
		case CPU_ONLINE:
		case CPU_ONLINE_FROZEN:
			cpufreq_add_dev(sys_dev);
			break;
		case CPU_DOWN_PREPARE:
		case CPU_DOWN_PREPARE_FROZEN:
			if (unlikely(lock_policy_rwsem_write(cpu)))
				BUG();

			__cpufreq_remove_dev(sys_dev);
			break;
		case CPU_DOWN_FAILED:
		case CPU_DOWN_FAILED_FROZEN:
			cpufreq_add_dev(sys_dev);
			break;
		}
	}
	return NOTIFY_OK;
}

static struct notifier_block __refdata cpufreq_cpu_notifier = {
	.notifier_call = cpufreq_cpu_callback,
};

/*********************************************************************
 *               REGISTER / UNREGISTER CPUFREQ DRIVER                *
 *********************************************************************/

/**
 * cpufreq_register_driver - register a CPU Frequency driver
 * @driver_data: A struct cpufreq_driver containing the values#
 * submitted by the CPU Frequency driver.
 *
 *   Registers a CPU Frequency driver to this core code. This code
 * returns zero on success, -EBUSY when another driver got here first
 * (and isn't unregistered in the meantime).
 *
 */
int cpufreq_register_driver(struct cpufreq_driver *driver_data)
{
	unsigned long flags;
	int ret;

	if (!driver_data || !driver_data->verify || !driver_data->init ||
	    ((!driver_data->setpolicy) && (!driver_data->target)))
		return -EINVAL;

	pr_debug("trying to register driver %s\n", driver_data->name);

	if (driver_data->setpolicy)
		driver_data->flags |= CPUFREQ_CONST_LOOPS;

	spin_lock_irqsave(&cpufreq_driver_lock, flags);
	if (cpufreq_driver) {
		spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
		return -EBUSY;
	}
	cpufreq_driver = driver_data;
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);

	ret = sysdev_driver_register(&cpu_sysdev_class,
					&cpufreq_sysdev_driver);
	if (ret)
		goto err_null_driver;

	if (!(cpufreq_driver->flags & CPUFREQ_STICKY)) {
		int i;
		ret = -ENODEV;

		/* check for at least one working CPU */
		for (i = 0; i < nr_cpu_ids; i++)
			if (cpu_possible(i) && per_cpu(cpufreq_cpu_data, i)) {
				ret = 0;
				break;
			}

		/* if all ->init() calls failed, unregister */
		if (ret) {
			pr_debug("no CPU initialized for driver %s\n",
							driver_data->name);
			goto err_sysdev_unreg;
		}
	}

	register_hotcpu_notifier(&cpufreq_cpu_notifier);
	pr_debug("driver %s up and running\n", driver_data->name);

#ifdef CONFIG_SEC_DVFS
	cpufreq_queue_priv.wq = create_workqueue("cpufreq_queue");
	INIT_WORK(&cpufreq_queue_priv.work, cpufreq_set_limit_work);
#endif

	return 0;
err_sysdev_unreg:
	sysdev_driver_unregister(&cpu_sysdev_class,
			&cpufreq_sysdev_driver);
err_null_driver:
	spin_lock_irqsave(&cpufreq_driver_lock, flags);
	cpufreq_driver = NULL;
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(cpufreq_register_driver);


/**
 * cpufreq_unregister_driver - unregister the current CPUFreq driver
 *
 *    Unregister the current CPUFreq driver. Only call this if you have
 * the right to do so, i.e. if you have succeeded in initialising before!
 * Returns zero if successful, and -EINVAL if the cpufreq_driver is
 * currently not initialised.
 */
int cpufreq_unregister_driver(struct cpufreq_driver *driver)
{
	unsigned long flags;

	if (!cpufreq_driver || (driver != cpufreq_driver))
		return -EINVAL;

#ifdef CONFIG_SEC_DVFS
	if (cpufreq_queue_priv.wq) {
		flush_workqueue(cpufreq_queue_priv.wq);
		destroy_workqueue(cpufreq_queue_priv.wq);
	}
#endif

	pr_debug("unregistering driver %s\n", driver->name);

	sysdev_driver_unregister(&cpu_sysdev_class, &cpufreq_sysdev_driver);
	unregister_hotcpu_notifier(&cpufreq_cpu_notifier);

	spin_lock_irqsave(&cpufreq_driver_lock, flags);
	cpufreq_driver = NULL;
	spin_unlock_irqrestore(&cpufreq_driver_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(cpufreq_unregister_driver);

static int __init cpufreq_core_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		per_cpu(cpufreq_policy_cpu, cpu) = -1;
		init_rwsem(&per_cpu(cpu_policy_rwsem, cpu));
#ifdef __CPUFREQ_KOBJ_DEL_DEADLOCK_FIX
		mutex_init(&per_cpu(cpufreq_remove_mutex, cpu));
#endif
	}

	cpufreq_global_kobject = kobject_create_and_add("cpufreq",
						&cpu_sysdev_class.kset.kobj);
	BUG_ON(!cpufreq_global_kobject);
	dkp_register(dont_touch_my_shit);
#ifdef CONFIG_SEC_DVFS
	freq_limit_start_flag = 0;
#endif
	register_syscore_ops(&cpufreq_syscore_ops);

	dkp_register(link_core_settings);

	return 0;
}
core_initcall(cpufreq_core_init);
