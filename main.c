/*
 * PS5 Firmware Spoofer
 * Utilizes GPU DMA to write to kernel .data section bypassing hypervisor protections when using direct kernel operations, sets PS4 SDK and PS5 update version to 99.99
 * Author: darkness
 * Tested on 11.20 - Confirmed working.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <ps5/kernel.h>

#define notify(...)        notify_(__VA_ARGS__)
#define DMEM_SIZE          (2ULL * 1024 * 1024)
#define PMAP_STORE_OFF     0x02E04F18ULL
#define ALLPROC_OFF        0x02875D70ULL
#define GVMSPACE_BASE_OFF  0x02E66570ULL
#define PROC_VM_SPACE_OFF  0x200
#define GVMSPACE_START_VA  0x08
#define GVMSPACE_SIZE_OFF  0x10
#define GVMSPACE_PAGE_DIR  0x38
#define SIZEOF_GVMSPACE    0x100
#define GPU_WALK_ADDR_MASK 0x0000ffffffffffc0ULL
#define GPU_VALID          (1ULL << 0)
#define GPU_IS_PTE         (1ULL << 54)
#define PROT_GPU_READ      0x10
#define PROT_GPU_WRITE     0x20
#define PROT_CPU_GPU_RW    (PROT_READ | PROT_WRITE | PROT_GPU_READ | PROT_GPU_WRITE)
#define PROT_CPU_GPU_RO    (PROT_READ | PROT_GPU_READ)
#define MAP_NO_COALESCE    0x400000
#define MAX_KCHUNK         2048
#define FW_MAX             0x99999999u

#if !defined(_countof)
    #define _countof(a) (sizeof(a) / sizeof(*a))
#endif
#if !defined(_countof_1)
    #define _countof_1(a) (_countof(a) - 1)
#endif

extern int sceKernelAllocateMainDirectMemory(size_t len, size_t alignment, int type, off_t* out);
extern int sceKernelMapNamedDirectMemory(void** addr, size_t len, int prot, int flags, off_t phys, size_t align, const char* name);

typedef struct {
    void*    cpu_va;
    uint64_t gpu_va;
    uint64_t pa;
} dmem_buf_t;

static int        g_gc_fd          = -1;
static uint64_t   g_dmap_base      =  0;
static uint64_t   g_kernel_cr3     =  0;
static uint64_t   g_gvmspace_base  =  0;
static uint32_t   g_vmid           =  0;
static uint64_t   g_victim_ptbe_va =  0;
static uint64_t   g_cleared_ptbe   =  0;
static uint64_t   g_original_ptbe  =  0;
static dmem_buf_t g_transfer       = {0};
static dmem_buf_t g_victim         = {0};
static dmem_buf_t g_cmd            = {0};

static void notify_(const char* fmt, ...)
{
    struct notify_request
    {
        char useless1[45];
        char message[1024];
        char useless2[2051];
    } buf = {};

    va_list args;
    va_start(args, fmt);
    vsnprintf(buf.message, _countof_1(buf.message), fmt, args);
    va_end(args);

    size_t len = strlen(buf.message);
    while (len > 0 && buf.message[len - 1] == '\n')
    {
        buf.message[--len] = '\0';
    }

    extern int sceKernelSendNotificationRequest(const size_t, const struct notify_request*, const size_t, const int);

    printf("%s\n", buf.message);
    sceKernelSendNotificationRequest(0, &buf, sizeof(buf), 0);
}

static void nanosleep_ms(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint64_t kread64(uintptr_t addr)
{
    uint64_t v = 0;
    kernel_copyout(addr, &v, 8);
    return v;
}

static uint32_t kread32(uintptr_t addr)
{
    uint32_t v = 0;
    kernel_copyout(addr, &v, 4);
    return v;
}

static uint64_t resolve_dmap_base(void)
{
    uintptr_t pmap_store = (uintptr_t)KERNEL_ADDRESS_DATA_BASE + PMAP_STORE_OFF;
    uint64_t pml4 = kread64(pmap_store + 0x20);
    uint64_t cr3  = kread64(pmap_store + 0x28);

    if (!cr3 || !pml4 || cr3 > pml4)
    {
		return 0;
	}

    g_kernel_cr3 = cr3;
    return pml4 - cr3;
}

static uint64_t cpu_virt_to_phys_cr3(uintptr_t vaddr, uint64_t cr3)
{
    uint64_t pml4e_idx = (vaddr >> 39) & 0x1ff;
    uint64_t pdpe_idx  = (vaddr >> 30) & 0x1ff;
    uint64_t pde_idx   = (vaddr >> 21) & 0x1ff;
    uint64_t pte_idx   = (vaddr >> 12) & 0x1ff;
    uint64_t entry     = 0;

    kernel_copyout(g_dmap_base + cr3 + pml4e_idx * 8, &entry, 8);
    if (!(entry & 1))
    {
		return 0;
	}

    kernel_copyout(g_dmap_base + (entry & 0x000ffffffffff000ULL) + pdpe_idx * 8, &entry, 8);
    if (!(entry & 1))
    {
		return 0;
	}

    kernel_copyout(g_dmap_base + (entry & 0x000ffffffffff000ULL) + pde_idx * 8, &entry, 8);
    if (!(entry & 1))
    {
		return 0;
	}

    if (entry & (1ULL << 7))
    {
        return (entry & 0x000fffffffe00000ULL) + (vaddr & 0x1fffff);
    }

    kernel_copyout(g_dmap_base + (entry & 0x000ffffffffff000ULL) + pte_idx * 8, &entry, 8);
    if (!(entry & 1))
    {
		return 0;
	}

    return (entry & 0x000ffffffffff000ULL) + (vaddr & 0xfff);
}

static uint64_t cpu_virt_to_phys(uintptr_t vaddr)
{
    return cpu_virt_to_phys_cr3(vaddr, g_kernel_cr3);
}

static uint64_t get_proc_cr3(void)
{
    uint64_t data_base     = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
    uint64_t allproc_first = kread64(data_base + ALLPROC_OFF);
    uint64_t vmspace       = kread64(allproc_first + PROC_VM_SPACE_OFF);
    uint64_t pmap_off      = 0;

    for (int i = 1; i <= 6; i++)
    {
        uint64_t val  = kread64(vmspace + 0x1C8 + i * 8);
        int64_t  diff = (int64_t)(val - vmspace);

        if (diff >= 0x2C0 && diff <= 0x2F0)
        {
			pmap_off = 0x1C8 + i * 8;
			break;
		}
    }

    if (!pmap_off)
    {
		return 0;
	}

    uint64_t pmap = kread64(vmspace + pmap_off);
    return kread64(pmap + 0x28);
}

static int alloc_dmem_buf(dmem_buf_t* buf, const char* name)
{
    off_t phys = 0;
    void* va   = NULL;
    int r1 = sceKernelAllocateMainDirectMemory(DMEM_SIZE, DMEM_SIZE, 1, &phys);

    if (r1 != 0)
    {
		notify("AllocateMainDirectMemory failed %s: 0x%08x\n", name, r1);
		return -1;
	}

    int r2 = sceKernelMapNamedDirectMemory(&va, DMEM_SIZE, PROT_CPU_GPU_RW, MAP_NO_COALESCE, phys, DMEM_SIZE, name);

    if (r2 != 0)
    {
		notify("MapNamedDirectMemory failed %s: 0x%08x\n", name, r2);
		return -1;
	}

    buf->cpu_va = va;
    buf->pa     = (uint64_t)phys;
    buf->gpu_va = (uint64_t)va;

    return 0;
}

static uint64_t gpu_walk_find_pte(uint64_t relative_va)
{
    uint64_t gvmspace  = g_gvmspace_base + (uint64_t)g_vmid * SIZEOF_GVMSPACE;
    uint64_t pdb2      = kread64(gvmspace + GVMSPACE_PAGE_DIR);
    if (!pdb2)
    {
		return 0;
	}

    uint64_t pml4e_idx = (relative_va >> 39) & 0x1ff;
    uint64_t pdpe_idx  = (relative_va >> 30) & 0x1ff;
    uint64_t pde_idx   = (relative_va >> 21) & 0x1ff;
    uint64_t pml4e     = kread64(pdb2 + pml4e_idx * 8);
    if (!(pml4e & GPU_VALID))
    {
		return 0;
	}

    uint64_t pdpe_va = g_dmap_base + (pml4e & GPU_WALK_ADDR_MASK) + pdpe_idx * 8;
    uint64_t pdpe    = kread64(pdpe_va);
    if (!(pdpe & GPU_VALID))
    {
		return 0;
	}

    uint64_t pde_va = g_dmap_base + (pdpe & GPU_WALK_ADDR_MASK) + pde_idx * 8;
    uint64_t pde    = kread64(pde_va);
    if (!(pde & GPU_VALID))
    {
		return 0;
	}

    return pde_va;
}

static int setup_gpu(void)
{
    uint64_t data_base     = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
    g_gvmspace_base        = data_base + GVMSPACE_BASE_OFF;
    uint64_t allproc_first = kread64(data_base + ALLPROC_OFF);
    uint64_t vmspace       = kread64(allproc_first + PROC_VM_SPACE_OFF);
    uint64_t pmap_off = 0;

    for (int i = 1; i <= 6; i++)
    {
        uint64_t val  = kread64(vmspace + 0x1C8 + i * 8);
        int64_t  diff = (int64_t)(val - vmspace);

        if (diff >= 0x2C0 && diff <= 0x2F0)
        {
			pmap_off = 0x1C8 + i * 8;
			break;
		}
    }

    if (!pmap_off)
    {
		notify("pmap offset scan failed\n");
		return -1;
	}

    for (int i = 1; i <= 8; i++)
    {
        uint32_t val = kread32(vmspace + 0x1D4 + i * 4);

        if (val > 0 && val <= 0x10)
        {
			g_vmid = val;
			break;
		}
    }

    if (!g_vmid)
    {
		notify("vmid scan failed\n");
		return -1;
	}

    uint64_t gvmspace      = g_gvmspace_base + (uint64_t)g_vmid * SIZEOF_GVMSPACE;
    uint64_t gpu_start     = kread64(gvmspace + GVMSPACE_START_VA);
    uint64_t gpu_size      = kread64(gvmspace + GVMSPACE_SIZE_OFF);
    uint64_t victim_cpu_va = (uint64_t)g_victim.cpu_va;

    if (victim_cpu_va < gpu_start || victim_cpu_va >= gpu_start + gpu_size)
    {
        notify("victim not in gpu vmspace\n");
        return -1;
    }

    g_victim_ptbe_va = gpu_walk_find_pte(victim_cpu_va - gpu_start);
    if (!g_victim_ptbe_va)
    {
		notify("gpu pte walk failed\n");
		return -1;
	}

    uint64_t proc_cr3 = get_proc_cr3();
    if (!proc_cr3)
    {
		notify("get_proc_cr3 failed\n");
		return -1;
	}

    uint64_t victim_real_pa = cpu_virt_to_phys_cr3(victim_cpu_va, proc_cr3);
    if (!victim_real_pa)
    {
		notify("v2p of victim failed\n");
		return -1;
	}

	mprotect(g_victim.cpu_va, DMEM_SIZE, PROT_CPU_GPU_RO);
	g_original_ptbe = kread64(g_victim_ptbe_va);
	g_cleared_ptbe = g_original_ptbe & (~victim_real_pa);
	mprotect(g_victim.cpu_va, DMEM_SIZE, PROT_CPU_GPU_RW);

    return 0;
}

static void gpu_submit_dma(uint64_t dst_gpu_va, uint64_t src_gpu_va, size_t size)
{
    uint32_t* cmd = (uint32_t*)g_cmd.cpu_va;
    cmd[0] = (3u << 30) | (1u << 1) | (0x50u << 8) | ((6 - 1) << 16);
    cmd[1] = (2u << 13) | (1u << 15) | (2u << 25) | (1u << 27) | (1u << 31);
    cmd[2] = (uint32_t)(src_gpu_va & 0xFFFFFFFF);
    cmd[3] = (uint32_t)(src_gpu_va >> 32);
    cmd[4] = (uint32_t)(dst_gpu_va & 0xFFFFFFFF);
    cmd[5] = (uint32_t)(dst_gpu_va >> 32);
    cmd[6] = (uint32_t)(size & 0x1FFFFF);

    uint64_t desc[2];
    desc[0] = ((g_cmd.gpu_va & 0xFFFFFFFF) << 32) | 0xC0023F00ULL;
    desc[1] = ((7ULL & 0xFFFFF) << 32) | ((g_cmd.gpu_va >> 32) & 0xFFFF);

    struct { uint32_t pipe_id; uint32_t cmd_count; uint64_t desc_ptr; } submit;
    submit.pipe_id   = 0;
    submit.cmd_count = 1;
    submit.desc_ptr  = (uint64_t)desc;
    ioctl(g_gc_fd, 0xC0108102, &submit);
    nanosleep_ms(500);
}

static void gpu_write_dword(uintptr_t kaddr, uint32_t val)
{
    uint64_t target_pa = cpu_virt_to_phys(kaddr);

    if (!target_pa)
    {
		return;
	}

    uint64_t trunc_pa = target_pa & ~(DMEM_SIZE - 1);
    uint64_t offset   = target_pa - trunc_pa;

    memcpy(g_transfer.cpu_va, &val, sizeof(val));
    mprotect(g_victim.cpu_va, DMEM_SIZE, PROT_CPU_GPU_RO);

    kernel_setlong(g_victim_ptbe_va, g_cleared_ptbe | trunc_pa);
    mprotect(g_victim.cpu_va, DMEM_SIZE, PROT_CPU_GPU_RW);

    gpu_submit_dma(g_victim.gpu_va + offset, g_transfer.gpu_va, sizeof(val));
    mprotect(g_victim.cpu_va, DMEM_SIZE, PROT_CPU_GPU_RO);

    kernel_setlong(g_victim_ptbe_va, g_original_ptbe);
    mprotect(g_victim.cpu_va, DMEM_SIZE, PROT_CPU_GPU_RW);
}

static uintptr_t kernel_scan(uintptr_t base, size_t limit, const void* needle, size_t nlen)
{
    if (!needle || nlen == 0 || nlen > MAX_KCHUNK)
    {
		return 0;
	}

    uint8_t buf[MAX_KCHUNK];
    size_t scanned = 0;

    while (limit == 0 || scanned < limit) {
        size_t chunk = sizeof(buf);

        if (limit && scanned + chunk > limit)
        {
			chunk = limit - scanned;
		}

        if (kernel_copyout(base + scanned, buf, chunk) != 0)
        {
			return 0;
		}

        for (size_t j = 0; j + nlen <= chunk; j++)
        {
            if (memcmp(buf + j, needle, nlen) == 0)
            {
				return base + scanned + j;
			}
		}
        scanned += chunk;
    }
    return 0;
}

static uintptr_t kernel_scan_strref(uintptr_t base, size_t limit, const void* s, size_t slen)
{
    uintptr_t str_addr = kernel_scan(base, limit, s, slen);

    if (!str_addr)
    {
		return 0;
	}

    str_addr += 1;
    return kernel_scan(base, limit, &str_addr, sizeof(str_addr));
}

static uintptr_t kernel_scan_near(uintptr_t addr, size_t range, const void* needle, size_t nlen)
{
    uintptr_t base = addr > range ? addr - range : 0;
    return kernel_scan(base, range * 2, needle, nlen);
}

static void cleanup(void)
{
    if (g_transfer.cpu_va)
    {
        munmap(g_transfer.cpu_va, DMEM_SIZE);
        g_transfer.cpu_va = NULL;
    }

    if (g_victim.cpu_va)
    {
        mprotect(g_victim.cpu_va, DMEM_SIZE, PROT_CPU_GPU_RW);
        munmap(g_victim.cpu_va, DMEM_SIZE);
        g_victim.cpu_va = NULL;
    }

    if (g_cmd.cpu_va)
    {
        munmap(g_cmd.cpu_va, DMEM_SIZE);
        g_cmd.cpu_va = NULL;
    }

    if (g_gc_fd >= 0)
    {
        close(g_gc_fd);
        g_gc_fd = -1;
    }
}

static void patch_fw(void)
{
    const char ps4_tag[] = "\0ps4_sdk_version\0";
    uintptr_t ps4_ref = kernel_scan_strref((uintptr_t)KERNEL_ADDRESS_DATA_BASE, 0, ps4_tag, sizeof(ps4_tag) - 1);

    if (ps4_ref)
	{
        gpu_write_dword(ps4_ref - 8, FW_MAX);
	}

    uint32_t upd_version = 0;
    size_t len = sizeof(upd_version);
    sysctlbyname("machdep.upd_version", &upd_version, &len, NULL, 0);

    if (upd_version)
    {
        uintptr_t upd_ref = kernel_scan_near((uintptr_t)KERNEL_ADDRESS_SECURITY_FLAGS, 4096, &upd_version, sizeof(upd_version));
        if (upd_ref)
        {
            gpu_write_dword(upd_ref, FW_MAX);
		}
	}

    /*const char sdk_tag[] = "\0sdk_version\0";
    uintptr_t sdk_ref = kernel_scan_strref((uintptr_t)KERNEL_ADDRESS_DATA_BASE, 0, sdk_tag, sizeof(sdk_tag) - 1);

    if (sdk_ref)
    {
        gpu_write_dword(sdk_ref - 8, FW_MAX);
	}*/
}

int main(void)
{
    setuid(0);

    g_dmap_base = resolve_dmap_base();

    if (!g_dmap_base)
    {
		notify("dmap resolve failed\n");
		return 1;
	}

    g_gc_fd = open("/dev/gc", O_RDWR);

    if (g_gc_fd < 0)
    {
		notify("open /dev/gc failed\n");
		return 1;
	}

    if (alloc_dmem_buf(&g_transfer, "transfer") != 0 || alloc_dmem_buf(&g_victim, "victim") != 0 || alloc_dmem_buf(&g_cmd, "cmd") != 0)
    {
		notify("dmem alloc failed\n");
        cleanup();
        return 1;
    }

    if (setup_gpu() != 0)
    {
        notify("gpu setup failed\n");
        cleanup();
        return 1;
    }

	uint32_t ps4_before = 0, /*sdk_before = 0,*/ upd_before = 0;
    uint32_t ps4_after = 0, /*sdk_after = 0,*/ upd_after = 0;
    size_t slen = sizeof(uint32_t);

    sysctlbyname("kern.ps4_sdk_version", &ps4_before, &slen, NULL, 0);
    //sysctlbyname("kern.sdk_version", &sdk_before, &slen, NULL, 0);
    sysctlbyname("machdep.upd_version", &upd_before, &slen, NULL, 0);

    patch_fw();

    sysctlbyname("kern.ps4_sdk_version", &ps4_after, &slen, NULL, 0);
    //sysctlbyname("kern.sdk_version", &sdk_after, &slen, NULL, 0);
    sysctlbyname("machdep.upd_version", &upd_after, &slen, NULL, 0);

    cleanup();

    notify("ps4_sdk_version: 0x%08x -> 0x%08x\n", ps4_before, ps4_after);
    //notify("sdk_version:     0x%08x -> 0x%08x\n", sdk_before, sdk_after);
    notify("upd_version:     0x%08x -> 0x%08x\n", upd_before, upd_after);

    return 0;
}
