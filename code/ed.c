/*
 * Memory Access Driver for Android v3.0
 * 内存读写驱动 - 支持游戏数据读取
 * 特性：随机节点名称、隐藏驱动节点、内存读写操作
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/highmem.h>
#include <linux/version.h>

// 随机设备名称生成
#define DEVICE_NAME_LEN 8
#define MAX_DEVICE_NAME_LEN 16

// IOCTL 命令定义
#define IOCTL_OP_INIT_KEY    0x800
#define IOCTL_OP_READ_MEM    0x801
#define IOCTL_OP_WRITE_MEM   0x802
#define IOCTL_OP_MODULE_BASE 0x803
#define IOCTL_OP_HIDE_DEVICE 0x804
#define IOCTL_OP_SHOW_DEVICE 0x805
#define IOCTL_OP_SET_AUTO_HIDE 0x806

// 内存操作结构体
struct memory_operation {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
    int read_write;  // 0x400 = read, 0x800 = write
};

// 模块基址结构体
struct module_base {
    pid_t pid;
    char *name;
    uintptr_t base;
};

// 驱动私有数据
struct mem_driver_data {
    struct device *char_dev;
    struct class *class;
    dev_t devt;
    struct cdev cdev;
    char device_name[MAX_DEVICE_NAME_LEN];
    bool is_hidden;
    int access_count;
    bool auto_hide_enabled;  // 自动隐藏功能
    int hide_after_access;   // 访问多少次后隐藏
    struct mutex hide_mutex; // 隐藏操作互斥锁
};

static struct mem_driver_data *mem_driver;
static char random_device_name[MAX_DEVICE_NAME_LEN];

// 函数声明
static void generate_random_device_name(char *name, int len);
static bool is_process_valid(pid_t pid);
static int read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
static int write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *module_name);
static void hide_device_node(void);
static void show_device_node(void);
static void check_auto_hide(void);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Memory Access Driver");
MODULE_DESCRIPTION("Memory Access Driver v3.0 - Game Data Reader");
MODULE_VERSION("3.0");

// 生成随机设备名称
static void generate_random_device_name(char *name, int len)
{
    char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int charset_size = sizeof(charset) - 1;
    int i, j;
    
    get_random_bytes(&i, sizeof(i));
    i = (i < 0) ? -i : i;
    
    for (j = 0; j < len - 1; j++) {
        name[j] = charset[i % charset_size];
        i = (i * 1103515245 + 12345) & 0x7fffffff; // 简单伪随机
    }
    name[len - 1] = '\0';
}

// 检查进程是否存在
static bool is_process_valid(pid_t pid)
{
    struct task_struct *task;
    bool valid = false;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task && task->mm) {
        valid = true;
    }
    rcu_read_unlock();
    
    return valid;
}

// 内存读取操作
static int read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page;
    void *kaddr;
    int ret = -EINVAL;
    
    if (!is_process_valid(pid)) {
        pr_err("mem_driver: Invalid process PID %d\n", pid);
        return -ESRCH;
    }
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task || !task->mm) {
        rcu_read_unlock();
        return -ESRCH;
    }
    
    mm = get_task_mm(task);
    rcu_read_unlock();
    
    if (!mm) {
        return -ESRCH;
    }
    
    down_read(&mm->mmap_lock);
    
    // 检查地址是否在有效范围内
    if (addr + size < addr || addr + size > TASK_SIZE) {
        pr_err("mem_driver: Invalid address range 0x%lx, size %zu\n", addr, size);
        goto out;
    }
    
    // 逐页读取内存
    while (size > 0) {
        size_t page_size = min(size, PAGE_SIZE - (addr & (PAGE_SIZE - 1)));
        struct page *pages[1];
        int locked = 0;
        
        ret = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, pages, NULL, &locked);
        if (ret != 1) {
            pr_err("mem_driver: Failed to get page for addr 0x%lx, ret=%d\n", addr, ret);
            if (ret > 0) {
                put_page(pages[0]);
            }
            ret = ret < 0 ? ret : -EFAULT;
            goto out;
        }
        
        page = pages[0];
        kaddr = kmap(page);
        if (!kaddr) {
            put_page(page);
            ret = -ENOMEM;
            goto out;
        }
        
        memcpy(buffer, kaddr + (addr & (PAGE_SIZE - 1)), page_size);
        kunmap(page);
        put_page(page);
        
        buffer += page_size;
        addr += page_size;
        size -= page_size;
    }
    
    ret = 0;
    
out:
    up_read(&mm->mmap_lock);
    mmput(mm);
    return ret;
}

// 内存写入操作
static int write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page;
    void *kaddr;
    int ret = -EINVAL;
    
    if (!is_process_valid(pid)) {
        pr_err("mem_driver: Invalid process PID %d\n", pid);
        return -ESRCH;
    }
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task || !task->mm) {
        rcu_read_unlock();
        return -ESRCH;
    }
    
    mm = get_task_mm(task);
    rcu_read_unlock();
    
    if (!mm) {
        return -ESRCH;
    }
    
    down_read(&mm->mmap_lock);
    
    // 检查地址是否在有效范围内
    if (addr + size < addr || addr + size > TASK_SIZE) {
        pr_err("mem_driver: Invalid address range 0x%lx, size %zu\n", addr, size);
        goto out;
    }
    
    // 逐页写入内存
    while (size > 0) {
        size_t page_size = min(size, PAGE_SIZE - (addr & (PAGE_SIZE - 1)));
        struct page *pages[1];
        int locked = 0;
        
        ret = get_user_pages_remote(mm, addr, 1, FOLL_FORCE | FOLL_WRITE, pages, NULL, &locked);
        if (ret != 1) {
            pr_err("mem_driver: Failed to get page for addr 0x%lx, ret=%d\n", addr, ret);
            if (ret > 0) {
                put_page(pages[0]);
            }
            ret = ret < 0 ? ret : -EFAULT;
            goto out;
        }
        
        page = pages[0];
        kaddr = kmap(page);
        if (!kaddr) {
            put_page(page);
            ret = -ENOMEM;
            goto out;
        }
        
        memcpy(kaddr + (addr & (PAGE_SIZE - 1)), buffer, page_size);
        kunmap(page);
        put_page(page);
        
        buffer += page_size;
        addr += page_size;
        size -= page_size;
    }
    
    ret = 0;
    
out:
    up_read(&mm->mmap_lock);
    mmput(mm);
    return ret;
}

// 获取模块基址
static uintptr_t get_module_base(pid_t pid, const char *module_name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base = 0;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task || !task->mm) {
        rcu_read_unlock();
        return 0;
    }
    
    mm = get_task_mm(task);
    rcu_read_unlock();
    
    if (!mm) {
        return 0;
    }
    
    down_read(&mm->mmap_lock);
    
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file && vma->vm_file->f_path.dentry) {
            const char *name = vma->vm_file->f_path.dentry->d_name.name;
            if (strstr(name, module_name)) {
                base = vma->vm_start;
                break;
            }
        }
    }
    
    up_read(&mm->mmap_lock);
    mmput(mm);
    
    return base;
}

// IOCTL 处理函数
static long mem_driver_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    
    switch (cmd) {
    case IOCTL_OP_INIT_KEY: {
        char key[256];
        if (copy_from_user(key, (void __user *)arg, sizeof(key))) {
            ret = -EFAULT;
            break;
        }
        pr_info("mem_driver: Init key: %s\n", key);
        break;
    }
    
    case IOCTL_OP_READ_MEM: {
        struct memory_operation mem_op;
        if (copy_from_user(&mem_op, (void __user *)arg, sizeof(mem_op))) {
            ret = -EFAULT;
            break;
        }
        
        if (mem_op.read_write == 0x400) { // 读取操作
            ret = read_process_memory(mem_op.pid, mem_op.addr, mem_op.buffer, mem_op.size);
    if (ret == 0) {
                if (copy_to_user((void __user *)arg, &mem_op, sizeof(mem_op))) {
                    ret = -EFAULT;
                }
            }
        } else {
            ret = -EINVAL;
        }
        break;
    }
    
    case IOCTL_OP_WRITE_MEM: {
        struct memory_operation mem_op;
        if (copy_from_user(&mem_op, (void __user *)arg, sizeof(mem_op))) {
            ret = -EFAULT;
            break;
        }
        
        if (mem_op.read_write == 0x800) { // 写入操作
            ret = write_process_memory(mem_op.pid, mem_op.addr, mem_op.buffer, mem_op.size);
    } else {
            ret = -EINVAL;
        }
        break;
    }
    
    case IOCTL_OP_MODULE_BASE: {
        struct module_base mod_base;
        if (copy_from_user(&mod_base, (void __user *)arg, sizeof(mod_base))) {
            ret = -EFAULT;
            break;
        }
        
        mod_base.base = get_module_base(mod_base.pid, mod_base.name);
        
        if (copy_to_user((void __user *)arg, &mod_base, sizeof(mod_base))) {
            ret = -EFAULT;
        }
        break;
    }
    
    case IOCTL_OP_HIDE_DEVICE: {
        pr_info("mem_driver: Manual hide request\n");
        hide_device_node();
        break;
    }
    
    case IOCTL_OP_SHOW_DEVICE: {
        pr_info("mem_driver: Manual show request\n");
        show_device_node();
        break;
    }
    
    case IOCTL_OP_SET_AUTO_HIDE: {
        int hide_count;
        if (copy_from_user(&hide_count, (void __user *)arg, sizeof(hide_count))) {
            ret = -EFAULT;
            break;
        }
        
        if (mem_driver) {
            mutex_lock(&mem_driver->hide_mutex);
            if (hide_count > 0) {
                mem_driver->auto_hide_enabled = true;
                mem_driver->hide_after_access = hide_count;
                pr_info("mem_driver: Auto-hide enabled, hide after %d accesses\n", hide_count);
            } else {
                mem_driver->auto_hide_enabled = false;
                pr_info("mem_driver: Auto-hide disabled\n");
            }
            mutex_unlock(&mem_driver->hide_mutex);
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
        mutex_lock(&mem_driver->hide_mutex);
        mem_driver->access_count++;
        pr_info("mem_driver: Device opened, access count: %d\n", mem_driver->access_count);
        
        // 检查是否需要自动隐藏
        check_auto_hide();
        
        mutex_unlock(&mem_driver->hide_mutex);
    }
    return 0;
}

static int mem_driver_release(struct inode *inode, struct file *file)
{
    if (mem_driver) {
        mutex_lock(&mem_driver->hide_mutex);
        mem_driver->access_count--;
        pr_info("mem_driver: Device closed, access count: %d\n", mem_driver->access_count);
        
        // 检查是否需要自动隐藏
        check_auto_hide();
        
        mutex_unlock(&mem_driver->hide_mutex);
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
                   "Hidden: %s\n"
                   "Access Count: %d\n"
                   "Status: Active\n",
                   mem_driver ? mem_driver->device_name : "Unknown",
                   mem_driver && mem_driver->is_hidden ? "Yes" : "No",
                   mem_driver ? mem_driver->access_count : 0);
    
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

// 隐藏设备节点
static void hide_device_node(void)
{
    if (!mem_driver) return;
    
    mutex_lock(&mem_driver->hide_mutex);
    
    if (mem_driver->char_dev && !mem_driver->is_hidden) {
        // 移除设备节点
        device_destroy(mem_driver->class, mem_driver->devt);
        mem_driver->char_dev = NULL;
        mem_driver->is_hidden = true;
        pr_info("mem_driver: Device node hidden (auto-hide)\n");
    }
    
    mutex_unlock(&mem_driver->hide_mutex);
}

// 显示设备节点
static void show_device_node(void)
{
    if (!mem_driver) return;
    
    mutex_lock(&mem_driver->hide_mutex);
    
    if (mem_driver->is_hidden) {
        // 重新创建设备节点
        mem_driver->char_dev = device_create(mem_driver->class, NULL, mem_driver->devt, 
                                           NULL, mem_driver->device_name);
        if (IS_ERR(mem_driver->char_dev)) {
            pr_err("mem_driver: Failed to recreate device\n");
            mem_driver->char_dev = NULL;
        } else {
            mem_driver->is_hidden = false;
            pr_info("mem_driver: Device node shown\n");
        }
    }
    
    mutex_unlock(&mem_driver->hide_mutex);
}

// 检查是否需要自动隐藏
static void check_auto_hide(void)
{
    if (!mem_driver || !mem_driver->auto_hide_enabled) return;
    
    if (mem_driver->access_count >= mem_driver->hide_after_access) {
        pr_info("mem_driver: Auto-hide triggered after %d accesses\n", mem_driver->access_count);
        hide_device_node();
    }
}

static int __init mem_driver_init(void)
{
    int ret;
    
    pr_alert("mem_driver: ===== INIT START =====\n");
    pr_alert("mem_driver: Initializing Memory Access Driver v3.0\n");
    
    // 分配驱动数据
    mem_driver = kzalloc(sizeof(*mem_driver), GFP_KERNEL);
    if (!mem_driver) {
        pr_err("mem_driver: Failed to allocate memory\n");
        return -ENOMEM;
    }
    
    // 初始化互斥锁
    mutex_init(&mem_driver->hide_mutex);
    
    // 设置默认自动隐藏参数
    mem_driver->auto_hide_enabled = true;
    mem_driver->hide_after_access = 1;  // 访问1次后自动隐藏
    
    // 生成随机设备名称
    generate_random_device_name(random_device_name, DEVICE_NAME_LEN);
    strncpy(mem_driver->device_name, random_device_name, MAX_DEVICE_NAME_LEN - 1);
    mem_driver->device_name[MAX_DEVICE_NAME_LEN - 1] = '\0';
    
    pr_info("mem_driver: Generated random device name: %s\n", mem_driver->device_name);
    
    // 分配字符设备号
    ret = alloc_chrdev_region(&mem_driver->devt, 0, 1, mem_driver->device_name);
    if (ret) {
        pr_err("mem_driver: Failed to allocate chrdev region\n");
        goto err_free_data;
    }
    
    // 初始化字符设备
    cdev_init(&mem_driver->cdev, &mem_driver_fops);
    mem_driver->cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&mem_driver->cdev, mem_driver->devt, 1);
    if (ret) {
        pr_err("mem_driver: Failed to add cdev\n");
        goto err_unreg_chrdev;
    }
    
    // 创建设备类
    mem_driver->class = class_create(THIS_MODULE, "mem_access");
    if (IS_ERR(mem_driver->class)) {
        pr_err("mem_driver: Failed to create device class\n");
        ret = PTR_ERR(mem_driver->class);
        goto err_del_cdev;
    }
    
    // 创建设备文件
    mem_driver->char_dev = device_create(mem_driver->class, NULL, mem_driver->devt, 
                                       NULL, mem_driver->device_name);
    if (IS_ERR(mem_driver->char_dev)) {
        pr_err("mem_driver: Failed to create device\n");
        ret = PTR_ERR(mem_driver->char_dev);
        goto err_destroy_class;
    }
    
    pr_alert("mem_driver: Memory access device created: /dev/%s\n", mem_driver->device_name);
    pr_alert("mem_driver: Device supports memory read/write operations\n");
    pr_alert("mem_driver: ===== INIT DONE =====\n");
    
    // 延迟隐藏设备节点（可选）
    // hide_device_node();
    
    return 0;
    
err_destroy_class:
    class_destroy(mem_driver->class);
err_del_cdev:
    cdev_del(&mem_driver->cdev);
err_unreg_chrdev:
    unregister_chrdev_region(mem_driver->devt, 1);
err_free_data:
    kfree(mem_driver);
    return ret;
}

static void __exit mem_driver_exit(void)
{
    pr_alert("mem_driver: ===== EXIT START =====\n");
    
    if (mem_driver) {
        if (mem_driver->char_dev)
            device_destroy(mem_driver->class, mem_driver->devt);
        if (mem_driver->class)
            class_destroy(mem_driver->class);
        cdev_del(&mem_driver->cdev);
        unregister_chrdev_region(mem_driver->devt, 1);
        
        kfree(mem_driver);
        mem_driver = NULL;
    }
    
    pr_alert("mem_driver: Memory Access Driver v3.0 unloaded\n");
    pr_alert("mem_driver: ===== EXIT DONE =====\n");
}

module_init(mem_driver_init);
module_exit(mem_driver_exit);
