/*
 * Memory Access Driver for Android v3.0
 * 内存读写驱动 - 支持游戏数据读取
 * 特性：随机节点名称、隐藏驱动节点、内存读写操作
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/time.h>
#include <linux/timekeeping.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Memory Access Driver");
MODULE_DESCRIPTION("Memory Access Driver v3.0 - Game Data Reader");

// 随机设备名称生成
#define DEVICE_NAME_LEN 8
#define MAX_DEVICE_NAME_LEN 16

// IOCTL 命令定义
#define IOCTL_OP_READ_MEM    0x801
#define IOCTL_OP_WRITE_MEM   0x802
#define IOCTL_OP_MODULE_BASE 0x803

// 调试日志文件路径（用于追踪初始化过程）
// Android系统中常用的可写路径：
// /data/local/tmp/ - 临时文件目录（推荐）
// /sdcard/ - 外部存储（某些系统可能无权限）
#define DEBUG_LOG_PATH "/data/local/tmp/mem_driver_init.log"

// 内存操作结构体
struct memory_operation {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
};

// 模块基址结构体
struct module_base {
    pid_t pid;
    char *name;
    uintptr_t base;
};

// 驱动数据结构
struct mem_driver_data {
    struct device *char_dev;
    struct class *class;
    dev_t devt;
    char device_name[MAX_DEVICE_NAME_LEN];
    int access_count;    // 当前打开的文件描述符数量
    int is_hidden;       // 节点是否已隐藏
};

static struct mem_driver_data *mem_driver = NULL;
static int major_number;

// 函数声明
static void generate_random_device_name(char *name, int len);
static int read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
static int write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *module_name);
static bool is_system_ready(void);
static void write_debug_log(const char *msg);

// 写入调试日志到文件（用于追踪初始化过程，即使系统重启也能查看）
static void write_debug_log(const char *msg)
{
    struct file *file;
    char log_buffer[512];
    int len;
    loff_t pos = 0;
    struct timespec64 ts;
    struct tm tm_result;
    
    // 获取当前时间
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm_result);
    
    // 格式化日志：[时间戳] [运行时间] 消息
    len = snprintf(log_buffer, sizeof(log_buffer),
                   "[%04ld-%02d-%02d %02d:%02d:%02d] [启动:%lu秒] %s\n",
                   tm_result.tm_year + 1900,
                   tm_result.tm_mon + 1,
                   tm_result.tm_mday,
                   tm_result.tm_hour,
                   tm_result.tm_min,
                   tm_result.tm_sec,
                   jiffies / HZ,  // 系统运行时间（秒）
                   msg);
    
    // 打开日志文件（追加模式）
    file = filp_open(DEBUG_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file)) {
        // 如果无法打开文件，只输出到内核日志
        pr_err("mem_driver: 无法打开日志文件 %s (err=%ld)\n", 
               DEBUG_LOG_PATH, PTR_ERR(file));
        pr_info("mem_driver: %s", msg);
        return;
    }
    
    // 写入日志
    pos = file->f_pos;
    kernel_write(file, log_buffer, len, &pos);
    file->f_pos = pos;
    
    // 强制同步到磁盘（确保即使崩溃也能看到日志）
    vfs_fsync(file, 0);
    
    // 关闭文件
    filp_close(file, NULL);
    
    // 同时输出到内核日志
    pr_info("mem_driver: %s", msg);
}

// 生成随机设备名称
static void generate_random_device_name(char *name, int len)
{
    char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int charset_size = sizeof(charset) - 1;
    int i, j;
    
    // 使用简单的伪随机数生成
    i = (int)jiffies;  // 使用内核时间戳作为种子
    
    for (j = 0; j < len - 1; j++) {
        name[j] = charset[i % charset_size];
        i = (i * 1103515245 + 12345) & 0x7fffffff; // 简单伪随机
    }
    name[len - 1] = '\0';
}

// 检查系统是否完全就绪（避免刚重启时加载导致卡死）
static bool is_system_ready(void)
{
    struct task_struct *init_task;
    struct pid *pid_struct;
    int i;
    pid_t test_pid;  // 修复：在函数开头声明变量，符合C89标准
    
    // 检查1：PID 1 (init进程) 必须存在
    pid_struct = find_get_pid(1);
    if (!pid_struct) {
        pr_warn("mem_driver: Init process not found, system not ready\n");
        return false;
    }
    
    init_task = pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!init_task) {
        pr_warn("mem_driver: Init task not found, system not ready\n");
        return false;
    }
    
    // 检查2：必须有多个用户态进程在运行（说明系统已经基本启动完成）
    // 检查是否有至少5个PID存在（1=init, 2=kthreadd, 还有其他用户进程）
    i = 0;
    for (test_pid = 1; test_pid < 100; test_pid++) {
        pid_struct = find_get_pid(test_pid);
        if (pid_struct) {
            put_pid(pid_struct);
            i++;
            if (i >= 5) {
                break;
            }
        }
    }
    
    if (i < 5) {
        pr_warn("mem_driver: Not enough processes running (%d), system not ready\n", i);
        return false;
    }
    
    // 检查3：等待至少5秒的系统运行时间（jiffies检查）
    // HZ是每秒的jiffies数，5*HZ就是5秒
    if (jiffies < 5 * HZ) {
        pr_warn("mem_driver: System uptime too short (%lu jiffies), system not ready\n", jiffies);
        return false;
    }
    
    pr_info("mem_driver: System ready check passed\n");
    return true;
}

// 获取进程的 task_struct
static struct task_struct* get_task_by_pid(pid_t pid)
{
    struct task_struct *task;
    struct pid *pid_struct;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        pr_err("mem_driver: PID %d not found\n", pid);
        return NULL;
    }
    
    task = pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task) {
        pr_err("mem_driver: Task for PID %d not found\n", pid);
        return NULL;
    }
    
    return task;
}

// 真正的内存读取操作
static int read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;
    unsigned long copied = 0;
    
    pr_info("mem_driver: Read request - PID:%d addr:0x%lx size:%zu\n", pid, addr, size);
    
    // 参数检查
    if (!buffer || size == 0 || size > 4096) {
        pr_err("mem_driver: Invalid parameters\n");
        return -EINVAL;
    }
    
    // 获取目标进程
    task = get_task_by_pid(pid);
    if (!task) {
        return -ESRCH;
    }
    
    // 获取进程内存描述符
    mm = get_task_mm(task);
    if (!mm) {
        pr_err("mem_driver: Failed to get mm for PID %d\n", pid);
        return -ESRCH;
    }
    
    // 使用 access_process_vm 读取内存
    // 这是内核提供的安全接口，用于访问其他进程的虚拟内存
    copied = access_process_vm(task, addr, buffer, size, 0);
    
    mmput(mm);
    
    if (copied != size) {
        pr_warn("mem_driver: Read incomplete - requested:%zu copied:%lu\n", size, copied);
        ret = copied > 0 ? 0 : -EFAULT;
    } else {
        pr_info("mem_driver: Read success - %zu bytes\n", size);
        ret = 0;
    }
    
    return ret;
}

// 真正的内存写入操作
static int write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;
    unsigned long copied = 0;
    
    pr_info("mem_driver: Write request - PID:%d addr:0x%lx size:%zu\n", pid, addr, size);
    
    // 参数检查
    if (!buffer || size == 0 || size > 4096) {
        pr_err("mem_driver: Invalid parameters\n");
        return -EINVAL;
    }
    
    // 获取目标进程
    task = get_task_by_pid(pid);
    if (!task) {
        return -ESRCH;
    }
    
    // 获取进程内存描述符
    mm = get_task_mm(task);
    if (!mm) {
        pr_err("mem_driver: Failed to get mm for PID %d\n", pid);
        return -ESRCH;
    }
    
    // 使用 access_process_vm 写入内存
    // FOLL_WRITE 标志表示写入操作
    copied = access_process_vm(task, addr, buffer, size, FOLL_WRITE);
    
    mmput(mm);
    
    if (copied != size) {
        pr_warn("mem_driver: Write incomplete - requested:%zu copied:%lu\n", size, copied);
        ret = copied > 0 ? 0 : -EFAULT;
    } else {
        pr_info("mem_driver: Write success - %zu bytes\n", size);
        ret = 0;
    }
    
    return ret;
}

// 获取模块基址（通过查找进程的内存映射）
static uintptr_t get_module_base(pid_t pid, const char *module_name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;
    
    pr_info("mem_driver: Module base request - PID:%d module:%s\n", 
            pid, module_name ? module_name : "NULL");
    
    if (!module_name || strlen(module_name) == 0) {
        pr_err("mem_driver: Invalid module name\n");
        return 0;
    }
    
    // 获取目标进程
    task = get_task_by_pid(pid);
    if (!task) {
        return 0;
    }
    
    // 获取进程内存描述符
    mm = get_task_mm(task);
    if (!mm) {
        pr_err("mem_driver: Failed to get mm for PID %d\n", pid);
        return 0;
    }
    
    // 遍历进程的内存映射区域
    down_read(&mm->mmap_lock);
    
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        // 检查是否是文件映射
        if (vma->vm_file) {
            const char *path;
            char *buf;
            
            buf = kmalloc(PATH_MAX, GFP_KERNEL);
            if (!buf)
                continue;
            
            path = d_path(&vma->vm_file->f_path, buf, PATH_MAX);
            if (!IS_ERR(path)) {
                // 检查路径是否包含模块名
                if (strstr(path, module_name)) {
                    // 找到第一个匹配的映射区域
                    base_addr = vma->vm_start;
                    pr_info("mem_driver: Found module %s at 0x%lx\n", 
                            module_name, base_addr);
                    kfree(buf);
                    break;
                }
            }
            
            kfree(buf);
        }
    }
    
    up_read(&mm->mmap_lock);
    mmput(mm);
    
    if (base_addr == 0) {
        pr_warn("mem_driver: Module %s not found in PID %d\n", module_name, pid);
    }
    
    return base_addr;
}

// IOCTL 处理函数
static long mem_driver_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    
    switch (cmd) {
    case IOCTL_OP_READ_MEM: {
        struct memory_operation mem_op;
        void *kernel_buf = NULL;
        
        if (copy_from_user(&mem_op, (void __user *)arg, sizeof(mem_op))) {
            ret = -EFAULT;
            break;
        }
        
        // 分配内核缓冲区
        kernel_buf = kmalloc(mem_op.size, GFP_KERNEL);
        if (!kernel_buf) {
            ret = -ENOMEM;
            break;
        }
        
        // 从目标进程读取内存到内核缓冲区
        ret = read_process_memory(mem_op.pid, mem_op.addr, kernel_buf, mem_op.size);
        
        if (ret == 0) {
            // 将数据从内核缓冲区复制到用户空间
            if (copy_to_user(mem_op.buffer, kernel_buf, mem_op.size)) {
                ret = -EFAULT;
            }
        }
        
        kfree(kernel_buf);
        break;
    }
    
    case IOCTL_OP_WRITE_MEM: {
        struct memory_operation mem_op;
        void *kernel_buf = NULL;
        
        if (copy_from_user(&mem_op, (void __user *)arg, sizeof(mem_op))) {
            ret = -EFAULT;
            break;
        }
        
        // 分配内核缓冲区
        kernel_buf = kmalloc(mem_op.size, GFP_KERNEL);
        if (!kernel_buf) {
            ret = -ENOMEM;
            break;
        }
        
        // 从用户空间复制数据到内核缓冲区
        if (copy_from_user(kernel_buf, mem_op.buffer, mem_op.size)) {
            kfree(kernel_buf);
            ret = -EFAULT;
            break;
        }
        
        // 将内核缓冲区的数据写入目标进程
        ret = write_process_memory(mem_op.pid, mem_op.addr, kernel_buf, mem_op.size);
        
        kfree(kernel_buf);
        break;
    }
    
    case IOCTL_OP_MODULE_BASE: {
        struct module_base mod_base;
        char *module_name_buf = NULL;
        
        if (copy_from_user(&mod_base, (void __user *)arg, sizeof(mod_base))) {
            ret = -EFAULT;
            break;
        }
        
        // 从用户空间复制模块名称
        if (mod_base.name) {
            module_name_buf = kmalloc(256, GFP_KERNEL);
            if (!module_name_buf) {
                ret = -ENOMEM;
                break;
            }
            
            if (copy_from_user(module_name_buf, mod_base.name, 255)) {
                kfree(module_name_buf);
                ret = -EFAULT;
                break;
            }
            module_name_buf[255] = '\0';
            
            // 获取模块基址
            mod_base.base = get_module_base(mod_base.pid, module_name_buf);
            
            kfree(module_name_buf);
        } else {
            mod_base.base = 0;
        }
        
        // 将结果返回给用户空间
        if (copy_to_user((void __user *)arg, &mod_base, sizeof(mod_base))) {
            ret = -EFAULT;
        }
        break;
    }
    
    
    default:
        ret = -ENOTTY;
        break;
    }
    
    return ret;
}

// 字符设备操作函数
static int mem_driver_open(struct inode *inode, struct file *file)
{
    if (mem_driver) {
        mem_driver->access_count++;
        
        // 第一次打开时自动隐藏节点
        if (mem_driver->access_count == 1 && !mem_driver->is_hidden) {
            if (mem_driver->char_dev) {
                device_destroy(mem_driver->class, mem_driver->devt);
                mem_driver->char_dev = NULL;
                mem_driver->is_hidden = 1;
            }
        }
    }
    return 0;
}

static int mem_driver_release(struct inode *inode, struct file *file)
{
    if (mem_driver) {
        mem_driver->access_count--;
        
        // 最后一个用户关闭时恢复节点
        if (mem_driver->access_count == 0 && mem_driver->is_hidden) {
            mem_driver->char_dev = device_create(mem_driver->class, NULL, 
                                                 mem_driver->devt, NULL, 
                                                 mem_driver->device_name);
            if (!IS_ERR(mem_driver->char_dev)) {
                mem_driver->is_hidden = 0;
            } else {
                mem_driver->char_dev = NULL;
            }
        }
    }
    return 0;
}

static ssize_t mem_driver_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    char msg[256];
    int len;
    
    if (*ppos > 0)
        return 0;
    
    len = snprintf(msg, sizeof(msg),
                   "Memory Access Driver v3.0\n"
                   "Device: %s\n"
                   "Access Count: %d\n"
                   "Hidden: %s\n"
                   "Status: Active\n",
                   mem_driver ? mem_driver->device_name : "Unknown",
                   mem_driver ? mem_driver->access_count : 0,
                   mem_driver && mem_driver->is_hidden ? "Yes" : "No");
    
    if (count < len)
        len = count;
    
    if (copy_to_user(buf, msg, len))
        return -EFAULT;
    
    *ppos += len;
    return len;
}

static struct file_operations mem_driver_fops = {
    .owner = THIS_MODULE,
    .open = mem_driver_open,
    .release = mem_driver_release,
    .read = mem_driver_read,
    .unlocked_ioctl = mem_driver_ioctl,
};

static int __init mem_driver_init(void)
{
    int ret;
    char random_name[MAX_DEVICE_NAME_LEN];
    char log_msg[256];
    
    // ========== 步骤1：开始初始化 ==========
    write_debug_log("========== 驱动初始化开始 ==========");
    write_debug_log("步骤1：开始初始化mem_driver模块");
    pr_info("mem_driver: Starting initialization...\n");
    
    // ========== 步骤2：系统就绪检查 ==========
    write_debug_log("步骤2：执行系统就绪检查（三重检查机制）");
    
    // ===【关键修复】检查系统是否完全就绪 ===
    // 这个检查会：
    // 1. 验证init进程存在
    // 2. 确保有足够的进程在运行
    // 3. 确保系统已经运行了至少5秒
    if (!is_system_ready()) {
        write_debug_log("步骤2：系统就绪检查失败，拒绝加载");
        write_debug_log("提示：请在系统启动30-60秒后再尝试加载驱动");
        write_debug_log("========== 驱动初始化失败（系统未就绪）==========");
        pr_err("mem_driver: System not ready, refusing to load. Please wait and retry.\n");
        pr_err("mem_driver: Tip: Wait at least 30-60 seconds after boot before loading.\n");
        return -EAGAIN;  // 返回EAGAIN表示"稍后重试"
    }
    
    write_debug_log("步骤2：系统就绪检查通过，继续初始化");
    
    // ========== 步骤3：分配驱动数据结构 ==========
    write_debug_log("步骤3：开始分配驱动数据结构（kzalloc）");
    mem_driver = kzalloc(sizeof(*mem_driver), GFP_KERNEL);
    if (!mem_driver) {
        write_debug_log("步骤3：分配驱动数据结构失败（内存不足）");
        write_debug_log("========== 驱动初始化失败（内存分配）==========");
        pr_err("mem_driver: Failed to allocate driver data\n");
        return -ENOMEM;
    }
    write_debug_log("步骤3：驱动数据结构分配成功");
    
    // ========== 步骤4：初始化驱动参数 ==========
    write_debug_log("步骤4：初始化驱动参数（access_count, is_hidden）");
    mem_driver->access_count = 0;
    mem_driver->is_hidden = 0;
    write_debug_log("步骤4：驱动参数初始化完成");
    
    // ========== 步骤5：生成随机设备名称 ==========
    write_debug_log("步骤5：开始生成随机设备名称");
    generate_random_device_name(random_name, DEVICE_NAME_LEN);
    strncpy(mem_driver->device_name, random_name, MAX_DEVICE_NAME_LEN - 1);
    mem_driver->device_name[MAX_DEVICE_NAME_LEN - 1] = '\0';
    
    snprintf(log_msg, sizeof(log_msg), "步骤5：设备名称生成完成：%s", mem_driver->device_name);
    write_debug_log(log_msg);
    pr_info("mem_driver: Generated device name: %s\n", mem_driver->device_name);
    
    // ========== 步骤6：注册字符设备 ==========
    write_debug_log("步骤6：开始注册字符设备（register_chrdev）");
    write_debug_log("警告：此步骤通常安全，但在某些内核版本可能有问题");
    
    major_number = register_chrdev(0, mem_driver->device_name, &mem_driver_fops);
    if (major_number < 0) {
        snprintf(log_msg, sizeof(log_msg), "步骤6：注册字符设备失败（ret=%d）", major_number);
        write_debug_log(log_msg);
        write_debug_log("========== 驱动初始化失败（注册字符设备）==========");
        pr_err("mem_driver: Failed to register chrdev (ret=%d)\n", major_number);
        ret = major_number;
        goto err_free_data;
    }
    
    mem_driver->devt = MKDEV(major_number, 0);
    snprintf(log_msg, sizeof(log_msg), "步骤6：字符设备注册成功（major=%d）", major_number);
    write_debug_log(log_msg);
    pr_info("mem_driver: Registered chrdev with major=%d\n", major_number);
    
    // ========== 步骤7：创建设备类（高风险操作）==========
    write_debug_log("步骤7：开始创建设备类（class_create）");
    write_debug_log("⚠️  关键步骤：此函数依赖sysfs子系统，系统未就绪时会卡死");
    write_debug_log("⚠️  如果系统在此处卡死，说明sysfs/kobject子系统未完全初始化");
    
    mem_driver->class = class_create(THIS_MODULE, "mem_access");
    
    write_debug_log("步骤7：class_create调用返回，正在检查结果");
    
    if (IS_ERR(mem_driver->class)) {
        ret = PTR_ERR(mem_driver->class);
        snprintf(log_msg, sizeof(log_msg), "步骤7：创建设备类失败（ret=%d）", ret);
        write_debug_log(log_msg);
        write_debug_log("========== 驱动初始化失败（创建设备类）==========");
        pr_err("mem_driver: Failed to create class (ret=%d)\n", ret);
        goto err_unreg_chrdev;
    }
    
    write_debug_log("步骤7：✅ 设备类创建成功（class_create通过）");
    pr_info("mem_driver: Created device class\n");
    
    // ========== 步骤8：创建设备文件（高风险操作）==========
    write_debug_log("步骤8：开始创建设备文件（device_create）");
    write_debug_log("⚠️  关键步骤：此函数依赖设备管理子系统，系统未就绪时会卡死");
    write_debug_log("⚠️  如果系统在此处卡死，说明设备管理子系统未完全初始化");
    
    mem_driver->char_dev = device_create(mem_driver->class, NULL, mem_driver->devt, 
                                        NULL, mem_driver->device_name);
    
    write_debug_log("步骤8：device_create调用返回，正在检查结果");
    
    if (IS_ERR(mem_driver->char_dev)) {
        ret = PTR_ERR(mem_driver->char_dev);
        snprintf(log_msg, sizeof(log_msg), "步骤8：创建设备文件失败（ret=%d）", ret);
        write_debug_log(log_msg);
        write_debug_log("========== 驱动初始化失败（创建设备文件）==========");
        pr_err("mem_driver: Failed to create device (ret=%d)\n", ret);
        goto err_destroy_class;
    }
    
    write_debug_log("步骤8：✅ 设备文件创建成功（device_create通过）");
    
    // ========== 步骤9：初始化完成 ==========
    snprintf(log_msg, sizeof(log_msg), 
             "步骤9：✅✅✅ 所有初始化步骤完成！设备节点：/dev/%s", 
             mem_driver->device_name);
    write_debug_log(log_msg);
    write_debug_log("========== 驱动初始化成功 ==========");
    
    pr_info("mem_driver: Initialization complete! Device: /dev/%s\n", mem_driver->device_name);
    return 0;
    
err_destroy_class:
    write_debug_log("错误处理：销毁设备类");
    class_destroy(mem_driver->class);
err_unreg_chrdev:
    write_debug_log("错误处理：注销字符设备");
    unregister_chrdev(major_number, mem_driver->device_name);
err_free_data:
    write_debug_log("错误处理：释放驱动数据");
    kfree(mem_driver);
    mem_driver = NULL;
    write_debug_log("========== 驱动初始化失败（错误处理完成）==========");
    pr_err("mem_driver: Initialization failed!\n");
    return ret;
}

static void __exit mem_driver_exit(void)
{
    write_debug_log("========== 驱动卸载开始 ==========");
    
    if (mem_driver) {
        write_debug_log("卸载步骤1：销毁设备文件");
        if (mem_driver->char_dev)
            device_destroy(mem_driver->class, mem_driver->devt);
        
        write_debug_log("卸载步骤2：销毁设备类");
        if (mem_driver->class)
            class_destroy(mem_driver->class);
        
        write_debug_log("卸载步骤3：注销字符设备");
        unregister_chrdev(major_number, mem_driver->device_name);
        
        write_debug_log("卸载步骤4：释放驱动数据");
        kfree(mem_driver);
        mem_driver = NULL;
        
        write_debug_log("========== 驱动卸载成功 ==========");
    } else {
        write_debug_log("警告：驱动数据为空，可能未正确初始化");
        write_debug_log("========== 驱动卸载完成（驱动未初始化）==========");
    }
}

module_init(mem_driver_init);
module_exit(mem_driver_exit);
