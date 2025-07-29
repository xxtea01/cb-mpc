#!/bin/bash

# CB-MPC 开发工具脚本
# 提供常用的开发和构建命令

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 检查是否在项目根目录
check_project_root() {
    if [ ! -f "CMakeLists.txt" ]; then
        print_error "请在项目根目录运行此脚本"
        exit 1
    fi
}

# 创建构建目录
create_build_dirs() {
    mkdir -p build/Release build/Debug
}

# 显示帮助信息
show_help() {
    echo "CB-MPC 开发工具"
    echo
    echo "用法: $0 [命令]"
    echo
    echo "可用命令:"
    echo "  build          - 构建Release版本"
    echo "  build-debug    - 构建Debug版本"
    echo "  test           - 运行Release测试"
    echo "  test-debug     - 运行Debug测试"
    echo "  clean          - 清理构建目录"
    echo "  go-build       - 构建Go应用"
    echo "  go-build-eth   - 构建ETH客户端"
    echo "  run-demo       - 运行Demo服务"
    echo "  install        - 安装C++库到系统"
    echo "  status         - 显示构建状态"
    echo "  help           - 显示此帮助"
    echo
    echo "示例:"
    echo "  $0 build       # 构建Release版本"
    echo "  $0 test        # 运行测试"
    echo "  $0 go-build    # 构建Go应用"
}

# 构建Release版本
build_release() {
    print_info "构建Release版本..."
    create_build_dirs
    cmake -B build/Release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
    cmake --build build/Release -- -j$(nproc)
    print_success "Release版本构建完成"
}

# 构建Debug版本
build_debug() {
    print_info "构建Debug版本..."
    create_build_dirs
    cmake -B build/Debug -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
    cmake --build build/Debug -- -j$(nproc)
    print_success "Debug版本构建完成"
}

# 运行Release测试
run_tests() {
    print_info "运行Release测试..."
    if [ ! -d "build/Release" ]; then
        print_warning "Release版本未构建，正在构建..."
        build_release
    fi
    cd build/Release && ctest --verbose
    print_success "Release测试完成"
}

# 运行Debug测试
run_tests_debug() {
    print_info "运行Debug测试..."
    if [ ! -d "build/Debug" ]; then
        print_warning "Debug版本未构建，正在构建..."
        build_debug
    fi
    cd build/Debug && ctest --verbose
    print_success "Debug测试完成"
}

# 清理构建目录
clean_build() {
    print_info "清理构建目录..."
    rm -rf build
    create_build_dirs
    print_success "构建目录已清理"
}

# 构建Go应用
build_go() {
    print_info "构建Go应用..."
    if [ ! -d "demos-go/cmd/threshold-ecdsa-web" ]; then
        print_error "未找到Go应用目录"
        exit 1
    fi
    
    # 确保C++库已构建
    if [ ! -d "build/Release" ]; then
        print_warning "C++库未构建，正在构建..."
        build_release
    fi
    
    # 安装C++库
    print_info "安装C++库..."
    make -C build/Release install
    
    # 构建Go应用
    cd demos-go/cmd/threshold-ecdsa-web
    CGO_ENABLED=1 go build -o demo-runner .
    print_success "Go应用构建完成"
}

# 构建ETH客户端
build_go_eth() {
    print_info "构建ETH客户端..."
    if [ ! -d "demos-go/cmd/eth-client" ]; then
        print_error "未找到ETH客户端目录"
        exit 1
    fi
    
    # 确保C++库已构建
    if [ ! -d "build/Release" ]; then
        print_warning "C++库未构建，正在构建..."
        build_release
    fi
    
    # 安装C++库
    print_info "安装C++库..."
    make -C build/Release install
    
    # 构建ETH客户端
    cd demos-go/cmd/eth-client
    CGO_ENABLED=1 go build -o eth-client .
    print_success "ETH客户端构建完成"
}

# 运行Demo服务
run_demo() {
    print_info "运行Demo服务..."
    if [ ! -f "demos-go/cmd/threshold-ecdsa-web/demo-runner" ]; then
        print_warning "Demo应用未构建，正在构建..."
        build_go
    fi
    
    cd demos-go/cmd/threshold-ecdsa-web
    ./demo-runner -index=0
}

# 安装C++库
install_libs() {
    print_info "安装C++库到系统..."
    if [ ! -d "build/Release" ]; then
        print_warning "Release版本未构建，正在构建..."
        build_release
    fi
    
    make -C build/Release install
    print_success "C++库安装完成"
}

# 显示构建状态
show_status() {
    print_info "构建状态:"
    echo
    
    if [ -d "build/Release" ]; then
        print_success "Release构建目录存在"
    else
        print_warning "Release构建目录不存在"
    fi
    
    if [ -d "build/Debug" ]; then
        print_success "Debug构建目录存在"
    else
        print_warning "Debug构建目录不存在"
    fi
    
    if [ -f "demos-go/cmd/threshold-ecdsa-web/demo-runner" ]; then
        print_success "Go应用已构建"
    else
        print_warning "Go应用未构建"
    fi
    
    if [ -f "demos-go/cmd/eth-client/eth-client" ]; then
        print_success "ETH客户端已构建"
    else
        print_warning "ETH客户端未构建"
    fi
    
    echo
    print_info "环境变量:"
    echo "CGO_ENABLED: ${CGO_ENABLED:-未设置}"
    echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH:-未设置}"
    echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-未设置}"
}

# 主函数
main() {
    check_project_root
    
    case "$1" in
        "build")
            build_release
            ;;
        "build-debug")
            build_debug
            ;;
        "test")
            run_tests
            ;;
        "test-debug")
            run_tests_debug
            ;;
        "clean")
            clean_build
            ;;
        "go-build")
            build_go
            ;;
        "go-build-eth")
            build_go_eth
            ;;
        "run-demo")
            run_demo
            ;;
        "install")
            install_libs
            ;;
        "status")
            show_status
            ;;
        "help"|"--help"|"-h"|"")
            show_help
            ;;
        *)
            print_error "未知命令: $1"
            echo
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@" 