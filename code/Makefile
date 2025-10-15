obj-m += ed.o

KERNEL_SRC ?= $(PWD)/../android_gki_5.10
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-

PWD := $(shell pwd)

all:
	@echo "========================================="
	@echo "编译内存读写驱动 v3.0"
	@echo "========================================="
	@if [ ! -d "$(KERNEL_SRC)" ]; then \
		echo "错误: GKI 内核源码目录 $(KERNEL_SRC) 不存在。"; \
		echo ""; \
		exit 1; \
	fi
	@echo "✅ 检测到 GKI 内核源码"
	@echo ""
	@echo "编译中..."
	$(MAKE) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		-C $(KERNEL_SRC) \
		M=$(PWD) \
		modules
	@echo ""
	@echo "✅ 编译完成！"
	@echo ""
	@if [ -f ed.ko ]; then \
		echo "✅ 模块文件已生成。"; \
		echo ""; \
		readelf -p .modinfo ed.ko | grep -E "vermagic|description"; \
		echo ""; \
		echo "此驱动支持内存读写操作！"; \
		echo "特性：随机节点名称、隐藏功能、游戏数据读取"; \
	else \
		echo "❌ 模块文件未找到。"; \
	fi

clean:
	@echo "清理编译文件..."
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean 2>/dev/null || true
	rm -f *.ko *.o *.mod.* .*.cmd modules.order Module.symvers
	rm -rf .tmp_versions

install:
	@echo "安装内存读写驱动..."
	@if [ -f ed.ko ]; then \
		echo "✅ 驱动模块已准备就绪"; \
		echo "使用加载驱动"; \
		echo "使用卸载驱动"; \
	else \
		echo "❌ 请先编译驱动模块"; \
	fi

help:
	@echo "可用命令："
	@echo "  make all     - 编译驱动模块"
	@echo "  make clean   - 清理编译文件"
	@echo "  make install - 显示安装说明"
	@echo "  make help    - 显示此帮助信息"
	@echo ""
	@echo "驱动特性："
	@echo "  - 随机设备节点名称"
	@echo "  - 设备节点隐藏功能"
	@echo "  - 内存读写操作"
	@echo "  - 模块基址获取"

	@echo "  - 兼容多种用户空间接口"


