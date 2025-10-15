/*
 * Memory Access Driver v3.0 - Header File
 * 内存读写驱动头文件 - 游戏数据读取版本
 */

#ifndef MEM_ACCESS_DRIVER_H
#define MEM_ACCESS_DRIVER_H

/* 版本信息 */
#define DRIVER_VERSION "3.0"
#define DRIVER_DESCRIPTION "Memory Access Driver v3.0 - Game Data Reader"

/* 设备名称配置 */
#define DEVICE_NAME_LEN 8
#define MAX_DEVICE_NAME_LEN 16

/* IOCTL 命令定义 */
#define IOCTL_OP_INIT_KEY    0x800
#define IOCTL_OP_READ_MEM    0x801
#define IOCTL_OP_WRITE_MEM    0x802
#define IOCTL_OP_MODULE_BASE 0x803
#define IOCTL_OP_HIDE_DEVICE 0x804
#define IOCTL_OP_SHOW_DEVICE 0x805
#define IOCTL_OP_SET_AUTO_HIDE 0x806

/* 内存操作类型 */
#define MEM_OP_READ  0x400
#define MEM_OP_WRITE 0x800

/* 内存操作结构体 */
struct memory_operation {
    pid_t pid;           // 目标进程PID
    uintptr_t addr;      // 内存地址
    void *buffer;        // 数据缓冲区
    size_t size;         // 数据大小
    int read_write;      // 操作类型：0x400=读，0x800=写
};

/* 模块基址结构体 */
struct module_base {
    pid_t pid;           // 目标进程PID
    char *name;          // 模块名称
    uintptr_t base;      // 模块基址
};

/* 
 * v3.0 版本特性：
 * - 随机生成设备节点名称，避免检测
 * - 支持设备节点隐藏/显示功能
 * - 完整的内存读写操作支持
 * - 进程内存访问权限检查
 * - 模块基址获取功能
 * - 兼容多种用户空间接口
 * 
 * 使用说明：
 * 
 * 1. 初始化密钥:
 *   ioctl(fd, IOCTL_OP_INIT_KEY, key_string);
 * 
 * 2. 读取内存:
 *   struct memory_operation mem_op = {
 *       .pid = target_pid,
 *       .addr = target_address,
 *       .buffer = data_buffer,
 *       .size = data_size,
 *       .read_write = MEM_OP_READ
 *   };
 *   ioctl(fd, IOCTL_OP_READ_MEM, &mem_op);
 * 
 * 3. 写入内存:
 *   struct memory_operation mem_op = {
 *       .pid = target_pid,
 *       .addr = target_address,
 *       .buffer = data_buffer,
 *       .size = data_size,
 *       .read_write = MEM_OP_WRITE
 *   };
 *   ioctl(fd, IOCTL_OP_WRITE_MEM, &mem_op);
 * 
 * 4. 获取模块基址:
 *   struct module_base mod_base = {
 *       .pid = target_pid,
 *       .name = "libil2cpp.so"
 *   };
 *   ioctl(fd, IOCTL_OP_MODULE_BASE, &mod_base);
 * 
 * 5. 手动隐藏设备:
 *   ioctl(fd, IOCTL_OP_HIDE_DEVICE, NULL);
 * 
 * 6. 手动显示设备:
 *   ioctl(fd, IOCTL_OP_SHOW_DEVICE, NULL);
 * 
 * 7. 设置自动隐藏:
 *   int hide_count = 1;  // 访问1次后隐藏
 *   ioctl(fd, IOCTL_OP_SET_AUTO_HIDE, &hide_count);
 * 
 * 8. 查看驱动状态:
 *   cat /dev/[随机设备名]
 * 
 * 9. 检查设备是否隐藏:
 *   ls /dev/ | grep [随机设备名]
 * 
 * 兼容性说明：
 * - 支持 Android 5.0+ 系统
 * - 兼容 GKI 内核架构
 * - 支持 ARM64 架构
 * - 兼容多种用户空间驱动接口
 */

#endif /* MEM_ACCESS_DRIVER_H */
