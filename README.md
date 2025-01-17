# CPP_Xmake_Env_Template

​	适配了VsCode的C++开发容器模板，使用Xake作为构建工具。

## 特性

- 自动安装交叉编译工具链(ARMV7)
- 启用CppCheck作为代码检查工具

## 快速上手

1. 安装VsCode

   - 下载地址：https://code.visualstudio.com/

2. 安装Docker

   - Ubuntu22.04

     - ```
       sudo apt update && sudo apt install docker-compose-v2
       ```

   - Ubuntu20.04

     - ```
       sudo apt update && sudo apt install docker-compose
       ```

3. 在VsCode中安装`Dev Containers`插件

4. 使用`Ctrl+Shift+p`快速打开命令面板，输入`dev container rebuild`

### 1、[使用xmake](https://xmake.io/#/zh-cn/)构建程序

- 将 toolchain-sunxi-musl 编译链改名 armv7-toolchain 下，放到当前 SDK 目录下，并确定 armv7-toolchain/toolchain/arm-openwrt-linux-muslgnueabi/ 存在
- 切换 V85x armv7 工具链：`xmake f -v -y -p linux -a armv7 --toolchain=armv7-toolchain --cross=arm-openwrt-linux-muslgnueabi-`
- 恢复初始化配置(工具链、构建模式)，改回 X86 本机编译:`xmake f -c -y`
- 如果需要头文件代码分析和跳转需要 xmake project -k cmake 生成cmake项目

- 构建项目：`xmake build`
  - 构建生成的文件位于  `Build/linux/<Arch>/<Mode>`目录下
- 切换构建模式：`xmake -m <debug/release>`
- xmake project -k cmake 生成cmake项目

### 2、使用CppCheck

右键需要检查的目录`Cpp-check-lint`->`cppcheck-dir`

## 项目结构

```
.
├── demo # 用于确认CppCheck是否正常工作的Demo
│   ├── src
│   │   └── main.cpp
│   └── xmake.lua
├── LICENSE
├── README.md
├── xmake.lua # 项目的构建配置
└── xmake-repo # xmake本地包仓库，收录一些xmake-io/xmake-repo中没有的软件包
    └── packages
        ├── c
        │   ├── cgraph
        │   │   └── xmake.lua
        │   └── c-periphery
        │       └── xmake.lua
        ├── h
        │   └── highway
        │       └── xmake.lua
        ├── n
        │   └── ne10
        │       └── xmake.lua
        ├── README.md
        └── z
            └── zbar
                └── xmake.lua

13 directories, 11 files
```

