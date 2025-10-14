/*
 * 字符设备驱动 - 挂载到 /dev
 * 适用于触摸设备等字符设备
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Custom Driver");
MODULE_DESCRIPTION("Character Device Driver for /dev");

#define DEVICE_NAME "mytouch"      // 设备名称
#define CLASS_NAME  "mytouch_class" // 设备类名

static int major_number;           // 主设备号
static struct class *dev_class;    // 设备类
static struct device *dev_device;  // 设备

static char message[256] = {0};    // 用于存储数据的缓冲区
static int message_size = 0;

// 设备打开
static int dev_open(struct inode *inode, struct file *file)
{
    pr_alert("mytouch: Device opened\n");
    return 0;
}

// 设备读取
static ssize_t dev_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    int bytes_read = 0;
    
    if (*offset >= message_size)
        return 0;
    
    if (*offset + len > message_size)
        len = message_size - *offset;
    
    if (copy_to_user(buf, message + *offset, len)) {
        pr_alert("mytouch: Failed to send data to user\n");
        return -EFAULT;
    }
    
    bytes_read = len;
    *offset += len;
    
    pr_alert("mytouch: Sent %d bytes to user\n", bytes_read);
    return bytes_read;
}

// 设备写入
static ssize_t dev_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    if (len > sizeof(message) - 1)
        len = sizeof(message) - 1;
    
    if (copy_from_user(message, buf, len)) {
        pr_alert("mytouch: Failed to receive data from user\n");
        return -EFAULT;
    }
    
    message_size = len;
    message[len] = '\0';
    
    pr_alert("mytouch: Received %zu bytes from user: %s\n", len, message);
    return len;
}

// 设备关闭
static int dev_release(struct inode *inode, struct file *file)
{
    pr_alert("mytouch: Device closed\n");
    return 0;
}

// ioctl 支持（用于触摸设备控制）
static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_alert("mytouch: ioctl called with cmd=0x%x, arg=0x%lx\n", cmd, arg);
    
    switch (cmd) {
        case 0x100:  // 示例命令
            pr_alert("mytouch: Command 0x100 executed\n");
            break;
        default:
            pr_alert("mytouch: Unknown command: 0x%x\n", cmd);
            return -EINVAL;
    }
    
    return 0;
}

// 文件操作结构
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
    .unlocked_ioctl = dev_ioctl,
};

// 模块初始化
static int __init char_device_init(void)
{
    pr_alert("========================================\n");
    pr_alert("mytouch: INIT START\n");
    pr_alert("========================================\n");
    
    // 注册字符设备
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_alert("mytouch: Failed to register character device: %d\n", major_number);
        return major_number;
    }
    pr_alert("mytouch: Registered with major number %d\n", major_number);
    
    // 创建设备类
    dev_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(dev_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        pr_alert("mytouch: Failed to create device class\n");
        return PTR_ERR(dev_class);
    }
    pr_alert("mytouch: Device class created\n");
    
    // 创建设备节点
    dev_device = device_create(dev_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(dev_device)) {
        class_destroy(dev_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        pr_alert("mytouch: Failed to create device\n");
        return PTR_ERR(dev_device);
    }
    
    pr_alert("mytouch: SUCCESS! Device created at /dev/%s\n", DEVICE_NAME);
    pr_alert("mytouch: Major number: %d\n", major_number);
    pr_alert("mytouch: Device class: %s\n", CLASS_NAME);
    pr_alert("========================================\n");
    
    sprintf(message, "Hello from %s driver!\nDevice is ready for touch input.\n", DEVICE_NAME);
    message_size = strlen(message);
    
    return 0;
}

// 模块卸载
static void __exit char_device_exit(void)
{
    pr_alert("========================================\n");
    pr_alert("mytouch: EXIT START\n");
    
    device_destroy(dev_class, MKDEV(major_number, 0));
    pr_alert("mytouch: Device destroyed\n");
    
    class_destroy(dev_class);
    pr_alert("mytouch: Device class destroyed\n");
    
    unregister_chrdev(major_number, DEVICE_NAME);
    pr_alert("mytouch: Character device unregistered\n");
    
    pr_alert("mytouch: Module unloaded\n");
    pr_alert("========================================\n");
}

module_init(char_device_init);
module_exit(char_device_exit);

