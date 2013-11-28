/* Copyright (c) 2002,2007-2012, The Linux Foundation. All rights reserved.
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
#include <linux/vmalloc.h>
#include <linux/memory_alloc.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <linux/kmemleak.h>

#include "kgsl.h"
#include "kgsl_sharedmem.h"
#include "kgsl_cffdump.h"
#include "kgsl_device.h"

#ifdef CONFIG_OUTER_CACHE
static void _outer_cache_range_op(int op, unsigned long addr, size_t size)
{
	switch (op) {
	case KGSL_CACHE_OP_FLUSH:
		outer_flush_range(addr, addr + size);
		break;
	case KGSL_CACHE_OP_CLEAN:
		outer_clean_range(addr, addr + size);
		break;
	case KGSL_CACHE_OP_INV:
		outer_inv_range(addr, addr + size);
		break;
	}
}

static void outer_cache_range_op_sg(struct scatterlist *sg, int sglen, int op)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, sglen, i) {
		unsigned int paddr = kgsl_get_sg_pa(s);
		_outer_cache_range_op(op, paddr, s->length);
	}
}

#else
static void outer_cache_range_op_sg(struct scatterlist *sg, int sglen, int op)
{
}
#endif

static int kgsl_vmalloc_vmfault(struct kgsl_memdesc *memdesc,
				struct vm_area_struct *vma,
				struct vm_fault *vmf)
{
	unsigned long offset;
	struct page *page;
	int i;

	offset = (unsigned long) vmf->virtual_address - vma->vm_start;

	i = offset >> PAGE_SHIFT;
	page = sg_page(&memdesc->sg[i]);
	if (page == NULL)
		return VM_FAULT_SIGBUS;

	get_page(page);

	vmf->page = page;
	return 0;
}

static int kgsl_vmalloc_vmflags(struct kgsl_memdesc *memdesc)
{
	return VM_RESERVED | VM_DONTEXPAND;
}

static void kgsl_vmalloc_free(struct kgsl_memdesc *memdesc)
{
	int i = 0;
	struct scatterlist *sg;
	if (memdesc->hostptr)
		vunmap(memdesc->hostptr);
	if (memdesc->sg)
		for_each_sg(memdesc->sg, sg, memdesc->sglen, i)
			__free_page(sg_page(sg));
}

static int kgsl_contiguous_vmflags(struct kgsl_memdesc *memdesc)
{
	return VM_RESERVED | VM_IO | VM_PFNMAP | VM_DONTEXPAND;
}

/*
 * kgsl_vmalloc_map_kernel - Map the memory in memdesc to kernel address space
 *
 * @memdesc - The memory descriptor which contains information about the memory
 *
 * Return: 0 on success else error code
 */
static int kgsl_vmalloc_map_kernel(struct kgsl_memdesc *memdesc)
{
	if (!memdesc->hostptr) {
		pgprot_t page_prot = pgprot_writecombine(PAGE_KERNEL);
		struct page **pages = NULL;
		struct scatterlist *sg;
		int i;
		/* create a list of pages to call vmap */
		pages = vmalloc(memdesc->sglen * sizeof(struct page *));
		if (!pages) {
			KGSL_CORE_ERR("vmalloc(%d) failed\n",
				memdesc->sglen * sizeof(struct page *));
			return -ENOMEM;
		}
		for_each_sg(memdesc->sg, sg, memdesc->sglen, i)
			pages[i] = sg_page(sg);
		memdesc->hostptr = vmap(pages, memdesc->sglen,
					VM_IOREMAP, page_prot);
		vfree(pages);
	}
	if (!memdesc->hostptr)
		return -ENOMEM;

	return 0;
}

static int kgsl_contiguous_vmfault(struct kgsl_memdesc *memdesc,
				struct vm_area_struct *vma,
				struct vm_fault *vmf)
{
	unsigned long offset, pfn;
	int ret;

	offset = ((unsigned long) vmf->virtual_address - vma->vm_start) >>
		PAGE_SHIFT;

	pfn = (memdesc->physaddr >> PAGE_SHIFT) + offset;
	ret = vm_insert_pfn(vma, (unsigned long) vmf->virtual_address, pfn);

	if (ret == -ENOMEM || ret == -EAGAIN)
		return VM_FAULT_OOM;
	else if (ret == -EFAULT)
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

static void kgsl_ebimem_free(struct kgsl_memdesc *memdesc)

{
	if (memdesc->hostptr)
		iounmap(memdesc->hostptr);

	free_contiguous_memory_by_paddr(memdesc->physaddr);
}

static void kgsl_coherent_free(struct kgsl_memdesc *memdesc)
{
	dma_free_coherent(NULL, memdesc->size,
			  memdesc->hostptr, memdesc->physaddr);
}

/* Global - also used by kgsl_drm.c */
struct kgsl_memdesc_ops kgsl_vmalloc_ops = {
	.free = kgsl_vmalloc_free,
	.vmflags = kgsl_vmalloc_vmflags,
	.vmfault = kgsl_vmalloc_vmfault,
	.map_kernel_mem = kgsl_vmalloc_map_kernel,
};
EXPORT_SYMBOL(kgsl_vmalloc_ops);

static struct kgsl_memdesc_ops kgsl_ebimem_ops = {
	.free = kgsl_ebimem_free,
	.vmflags = kgsl_contiguous_vmflags,
	.vmfault = kgsl_contiguous_vmfault,
};

static struct kgsl_memdesc_ops kgsl_coherent_ops = {
	.free = kgsl_coherent_free,
};

void kgsl_cache_range_op(struct kgsl_memdesc *memdesc, int op)
{
	void *addr = memdesc->hostptr;
	int size = memdesc->size;

	switch (op) {
	case KGSL_CACHE_OP_FLUSH:
		dmac_flush_range(addr, addr + size);
		break;
	case KGSL_CACHE_OP_CLEAN:
		dmac_clean_range(addr, addr + size);
		break;
	case KGSL_CACHE_OP_INV:
		dmac_inv_range(addr, addr + size);
		break;
	}

	outer_cache_range_op_sg(memdesc->sg, memdesc->sglen, op);
}
EXPORT_SYMBOL(kgsl_cache_range_op);

static int
_kgsl_sharedmem_vmalloc(struct kgsl_memdesc *memdesc,
			struct kgsl_pagetable *pagetable,
			size_t size, unsigned int protflags)
{
	int ret = 0;
	int sglen = PAGE_ALIGN(size) / PAGE_SIZE;
	int i;

	memdesc->size = size;
	memdesc->pagetable = pagetable;
	memdesc->priv = KGSL_MEMFLAGS_CACHED;
	memdesc->ops = &kgsl_vmalloc_ops;

	memdesc->sglen = sglen;
	memdesc->sg = kgsl_sg_alloc(sglen);

	if (memdesc->sg == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	kmemleak_not_leak(memdesc->sg);

	sg_init_table(memdesc->sg, sglen);

	for (i = 0; i < memdesc->sglen; i++) {
		struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO |
						__GFP_HIGHMEM);
		if (!page) {
			ret = -ENOMEM;
			memdesc->sglen = i;
			goto done;
		}
		flush_dcache_page(page);
		sg_set_page(&memdesc->sg[i], page, PAGE_SIZE, 0);
	}
	outer_cache_range_op_sg(memdesc->sg, memdesc->sglen,
				KGSL_CACHE_OP_FLUSH);

	ret = kgsl_mmu_map(pagetable, memdesc, protflags);

	if (ret)
		goto done;

done:
	if (ret)
		kgsl_sharedmem_free(memdesc);

	return ret;
}

int
kgsl_sharedmem_vmalloc(struct kgsl_memdesc *memdesc,
		       struct kgsl_pagetable *pagetable, size_t size)
{
	int ret = 0;
	BUG_ON(size == 0);

	size = ALIGN(size, PAGE_SIZE * 2);

	ret =  _kgsl_sharedmem_vmalloc(memdesc, pagetable, size,
		GSL_PT_PAGE_RV | GSL_PT_PAGE_WV);
	if (!ret)
		ret = kgsl_vmalloc_map_kernel(memdesc);
	if (ret)
		kgsl_sharedmem_free(memdesc);
	return ret;
}
EXPORT_SYMBOL(kgsl_sharedmem_vmalloc);

int
kgsl_sharedmem_vmalloc_user(struct kgsl_memdesc *memdesc,
			    struct kgsl_pagetable *pagetable,
			    size_t size, int flags)
{
	unsigned int protflags;

	BUG_ON(size == 0);

	protflags = GSL_PT_PAGE_RV;
	if (!(flags & KGSL_MEMFLAGS_GPUREADONLY))
		protflags |= GSL_PT_PAGE_WV;

	return _kgsl_sharedmem_vmalloc(memdesc, pagetable, size,
		protflags);
}
EXPORT_SYMBOL(kgsl_sharedmem_vmalloc_user);

int
kgsl_sharedmem_alloc_coherent(struct kgsl_memdesc *memdesc, size_t size)
{
	int result = 0;

	size = ALIGN(size, PAGE_SIZE);

	memdesc->size = size;
	memdesc->ops = &kgsl_coherent_ops;

	memdesc->hostptr = dma_alloc_coherent(NULL, size, &memdesc->physaddr,
					      GFP_KERNEL);
	if (memdesc->hostptr == NULL) {
		KGSL_CORE_ERR("dma_alloc_coherent(%d) failed\n", size);
		result = -ENOMEM;
		goto err;
	}

	result = memdesc_sg_phys(memdesc, memdesc->physaddr, size);
	if (result)
		goto err;

err:
	if (result)
		kgsl_sharedmem_free(memdesc);

	return result;
}
EXPORT_SYMBOL(kgsl_sharedmem_alloc_coherent);

void kgsl_sharedmem_free(struct kgsl_memdesc *memdesc)
{
	if (memdesc == NULL || memdesc->size == 0)
		return;

	if (memdesc->gpuaddr)
		kgsl_mmu_unmap(memdesc->pagetable, memdesc);

	if (memdesc->ops && memdesc->ops->free)
		memdesc->ops->free(memdesc);

	kgsl_sg_free(memdesc->sg, memdesc->sglen);

	memset(memdesc, 0, sizeof(*memdesc));
}
EXPORT_SYMBOL(kgsl_sharedmem_free);

static int
_kgsl_sharedmem_ebimem(struct kgsl_memdesc *memdesc,
			struct kgsl_pagetable *pagetable, size_t size)
{
	int result = 0;

	memdesc->size = size;
	memdesc->pagetable = pagetable;
	memdesc->ops = &kgsl_ebimem_ops;
	memdesc->physaddr = allocate_contiguous_ebi_nomap(size, SZ_8K);

	if (memdesc->physaddr == 0) {
		KGSL_CORE_ERR("allocate_contiguous_ebi_nomap(%d) failed\n",
			size);
		return -ENOMEM;
	}

	result = memdesc_sg_phys(memdesc, memdesc->physaddr, size);

	if (result)
		goto err;

	result = kgsl_mmu_map(pagetable, memdesc,
		GSL_PT_PAGE_RV | GSL_PT_PAGE_WV);

	if (result)
		goto err;

err:
	if (result)
		kgsl_sharedmem_free(memdesc);

	return result;
}

int
kgsl_sharedmem_ebimem_user(struct kgsl_memdesc *memdesc,
			struct kgsl_pagetable *pagetable,
			size_t size, int flags)
{
	size = ALIGN(size, PAGE_SIZE);
	return _kgsl_sharedmem_ebimem(memdesc, pagetable, size);
}
EXPORT_SYMBOL(kgsl_sharedmem_ebimem_user);

int
kgsl_sharedmem_ebimem(struct kgsl_memdesc *memdesc,
		struct kgsl_pagetable *pagetable, size_t size)
{
	int result;
	size = ALIGN(size, 8192);
	result = _kgsl_sharedmem_ebimem(memdesc, pagetable, size);

	if (result)
		return result;

	memdesc->hostptr = ioremap(memdesc->physaddr, size);

	if (memdesc->hostptr == NULL) {
		KGSL_CORE_ERR("ioremap failed\n");
		kgsl_sharedmem_free(memdesc);
		return -ENOMEM;
	}

	return 0;
}
EXPORT_SYMBOL(kgsl_sharedmem_ebimem);

int
kgsl_sharedmem_readl(const struct kgsl_memdesc *memdesc,
			uint32_t *dst,
			unsigned int offsetbytes)
{
	uint32_t *src;
	BUG_ON(memdesc == NULL || memdesc->hostptr == NULL || dst == NULL);
	WARN_ON(offsetbytes % sizeof(uint32_t) != 0);
	if (offsetbytes % sizeof(uint32_t) != 0)
		return -EINVAL;

	WARN_ON(offsetbytes + sizeof(uint32_t) > memdesc->size);
	if (offsetbytes + sizeof(uint32_t) > memdesc->size)
		return -ERANGE;
	src = (uint32_t *)(memdesc->hostptr + offsetbytes);
	*dst = *src;
	return 0;
}
EXPORT_SYMBOL(kgsl_sharedmem_readl);

int
kgsl_sharedmem_writel(const struct kgsl_memdesc *memdesc,
			unsigned int offsetbytes,
			uint32_t src)
{
	uint32_t *dst;
	BUG_ON(memdesc == NULL || memdesc->hostptr == NULL);
	WARN_ON(offsetbytes % sizeof(uint32_t) != 0);
	if (offsetbytes % sizeof(uint32_t) != 0)
		return -EINVAL;

	WARN_ON(offsetbytes + sizeof(uint32_t) > memdesc->size);
	if (offsetbytes + sizeof(uint32_t) > memdesc->size)
		return -ERANGE;
	kgsl_cffdump_setmem(memdesc->gpuaddr + offsetbytes,
		src, sizeof(uint32_t));
	dst = (uint32_t *)(memdesc->hostptr + offsetbytes);
	*dst = src;
	return 0;
}
EXPORT_SYMBOL(kgsl_sharedmem_writel);

int
kgsl_sharedmem_set(const struct kgsl_memdesc *memdesc, unsigned int offsetbytes,
			unsigned int value, unsigned int sizebytes)
{
	BUG_ON(memdesc == NULL || memdesc->hostptr == NULL);
	BUG_ON(offsetbytes + sizebytes > memdesc->size);

	kgsl_cffdump_setmem(memdesc->gpuaddr + offsetbytes, value,
			    sizebytes);
	memset(memdesc->hostptr + offsetbytes, value, sizebytes);
	return 0;
}
EXPORT_SYMBOL(kgsl_sharedmem_set);

/*
 * kgsl_sharedmem_map_vma - Map a user vma to physical memory
 *
 * @vma - The user vma to map
 * @memdesc - The memory descriptor which contains information about the
 * physical memory
 *
 * Return: 0 on success else error code
 */
int
kgsl_sharedmem_map_vma(struct vm_area_struct *vma,
			const struct kgsl_memdesc *memdesc)
{
	unsigned long addr = vma->vm_start;
	unsigned long size = vma->vm_end - vma->vm_start;
	int ret, i = 0;

	if (!memdesc->sg || (size != memdesc->size) ||
		(memdesc->sglen != (size / PAGE_SIZE)))
		return -EINVAL;

	for (; addr < vma->vm_end; addr += PAGE_SIZE, i++) {
		ret = vm_insert_page(vma, addr, sg_page(&memdesc->sg[i]));
		if (ret)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(kgsl_sharedmem_map_vma);
