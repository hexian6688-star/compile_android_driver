# 内存读写驱动 v3.0 使用说明

## 概述

这是一个专为游戏数据读取设计的内核驱动，具有以下特性：

- **随机设备节点名称**：每次加载生成随机的8位设备名，避免被检测
- **设备节点隐藏功能**：支持动态隐藏/显示设备节点
- **完整内存读写操作**：支持进程内存的读取和写入
- **模块基址获取**：可以获取目标进程中模块的基址
- **兼容多种接口**：兼容现有的用户空间驱动接口

## 文件结构

```
code/
├── det.c              # 主驱动源码
├── det.h              # 头文件定义
├── Makefile           # 驱动编译配置
├── test_mem_driver.c  # 测试程序源码
├── Makefile.test      # 测试程序编译配置
└── README.md          # 本说明文档
```

## 编译和安装

### 1. 编译驱动模块

```bash
cd code/
make all
```

编译成功后会在当前目录生成 `det.ko` 文件。

### 2. 加载驱动

```bash
# 加载驱动模块
insmod det.ko

# 查看加载状态
lsmod | grep det

# 查看设备节点（随机名称）
ls /dev/ | grep -E '^[a-z0-9]{8}$'
```

### 3. 编译测试程序

```bash
# 编译测试程序
make -f Makefile.test all

# 运行测试
./test_mem_driver <进程名>
```

## 驱动接口说明

### IOCTL 命令

| 命令 | 值 | 功能 |
|------|----|----- |
| IOCTL_OP_INIT_KEY | 0x800 | 初始化密钥 |
| IOCTL_OP_READ_MEM | 0x801 | 读取内存 |
| IOCTL_OP_WRITE_MEM | 0x802 | 写入内存 |
| IOCTL_OP_MODULE_BASE | 0x803 | 获取模块基址 |

### 数据结构

#### 内存操作结构体
```c
struct memory_operation {
    pid_t pid;           // 目标进程PID
    uintptr_t addr;      // 内存地址
    void *buffer;        // 数据缓冲区
    size_t size;         // 数据大小
    int read_write;      // 操作类型：0x400=读，0x800=写
};
```

#### 模块基址结构体
```c
struct module_base {
    pid_t pid;           // 目标进程PID
    char *name;          // 模块名称
    uintptr_t base;      // 模块基址
};
```

## 使用示例

### C/C++ 接口示例

```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

// 打开设备（需要先找到随机设备名）
int fd = open("/dev/abc12345", O_RDWR);

// 初始化密钥
char key[] = "my_secret_key";
ioctl(fd, IOCTL_OP_INIT_KEY, key);

// 读取内存
struct memory_operation mem_op = {
    .pid = target_pid,
    .addr = 0x400000,
    .buffer = buffer,
    .size = 16,
    .read_write = MEM_OP_READ
};
ioctl(fd, IOCTL_OP_READ_MEM, &mem_op);

// 获取模块基址
struct module_base mod_base = {
    .pid = target_pid,
    .name = "libil2cpp.so"
};
ioctl(fd, IOCTL_OP_MODULE_BASE, &mod_base);
```

### 兼容现有接口

本驱动完全兼容 `hexian.hpp` 中定义的接口：

```cpp
// 使用现有的 c_driver 类
c_driver *driver = new c_driver();

// 初始化
driver->initialize(target_pid);

// 读取内存
driver->Read(address, buffer, size);

// 写入内存
driver->write(address, value);

// 获取模块基址
uintptr_t base = driver->getModuleBase("libil2cpp.so");
```

## 设备节点查找

由于设备节点名称是随机的，需要通过以下方式查找：

### 1. 程序自动查找
```c
char* find_random_device() {
    DIR *dir = opendir("/dev");
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strlen(entry->d_name) == 8) {
            // 检查是否是8位小写字母数字组合
            // 尝试打开并验证设备信息
        }
    }
}
```

### 2. 命令行查找
```bash
# 查找8位随机设备名
ls /dev/ | grep -E '^[a-z0-9]{8}$'

# 验证设备信息
cat /dev/[设备名]
```

## 隐藏功能详解

### 1. 自动隐藏机制

驱动默认启用自动隐藏功能，访问1次后自动隐藏设备节点：

```c
// 默认设置
mem_driver->auto_hide_enabled = true;
mem_driver->hide_after_access = 1;  // 访问1次后隐藏
```

### 2. 手动控制隐藏

```c
// 手动隐藏设备
ioctl(fd, IOCTL_OP_HIDE_DEVICE, NULL);

// 手动显示设备
ioctl(fd, IOCTL_OP_SHOW_DEVICE, NULL);

// 设置自动隐藏参数
int hide_count = 2;  // 访问2次后隐藏
ioctl(fd, IOCTL_OP_SET_AUTO_HIDE, &hide_count);
```

### 3. 隐藏行为

- **设备节点消失**：隐藏后 `/dev/[设备名]` 文件消失
- **程序无法找到**：再次运行程序时无法找到设备节点
- **内核日志记录**：所有隐藏操作都会记录在内核日志中
- **线程安全**：使用互斥锁保护隐藏操作

### 4. 使用场景

```bash
# 第一次运行程序
./test_mem_driver com.example.game
# 输出: ✅ 找到驱动设备: /dev/abc12345

# 第二次运行程序（设备已隐藏）
./test_mem_driver com.example.game  
# 输出: ❌ 未找到内存读写驱动设备
```

### 5. 演示程序

运行隐藏功能演示：
```bash
gcc -o demo_hide demo_hide.c
./demo_hide
```

## 卸载驱动

```bash
# 卸载驱动模块
rmmod det

# 清理编译文件
make clean
```

## 注意事项

1. **权限要求**：需要 root 权限才能加载和使用驱动
2. **内核版本**：支持 Android 5.0+ 和 GKI 内核
3. **架构支持**：目前支持 ARM64 架构
4. **进程保护**：某些系统进程可能受到 SELinux 保护
5. **内存对齐**：建议按页边界对齐内存操作

## 故障排除

### 常见问题

1. **设备未找到**
   - 检查驱动是否已加载：`lsmod | grep det`
   - 检查设备节点：`ls /dev/ | grep -E '^[a-z0-9]{8}$'`

2. **权限被拒绝**
   - 确保以 root 权限运行
   - 检查 SELinux 状态：`getenforce`

3. **内存访问失败**
   - 检查目标进程是否存在
   - 验证内存地址是否有效
   - 检查进程内存保护

4. **编译错误**
   - 确保内核源码路径正确
   - 检查交叉编译工具链
   - 验证内核版本兼容性

## 技术支持

如有问题，请检查：

1. 内核日志：`dmesg | grep mem_driver`
2. 系统日志：`logcat | grep mem_driver`
3. 设备状态：`cat /dev/[设备名]`

## 版本历史

- **v3.0**：完全重写，支持随机节点名称和隐藏功能
- **v2.2**：虚拟触摸输入驱动版本
- **v2.0**：基础触摸输入驱动版本