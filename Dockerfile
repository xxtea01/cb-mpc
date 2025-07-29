# 多阶段构建MPC项目
# 阶段1: 构建C++核心库
FROM ubuntu:22.04 AS cpp-builder

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    curl \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    libtool \
    autoconf \
    automake \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /workspace

# 复制项目文件
COPY . .

# 构建C++核心库
RUN mkdir -p build/Release && \
    cmake -B build/Release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON && \
    cmake --build build/Release -- -j$(nproc)

# 安装C++库到系统
RUN make -C build/Release install

# 阶段2: 构建Go应用
FROM golang:1.21 AS go-builder

# 安装必要的系统依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /workspace

# 复制项目文件
COPY . .

# 复制C++库文件
COPY --from=cpp-builder /usr/local/lib /usr/local/lib
COPY --from=cpp-builder /usr/local/include /usr/local/include

# 设置环境变量
ENV CGO_ENABLED=1
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/lib

# 构建Go应用
RUN cd demos-go/cmd/threshold-ecdsa-web && \
    CGO_ENABLED=1 go build -o demo-runner .

# 构建ETH客户端
RUN cd demos-go/cmd/eth-client && \
    CGO_ENABLED=1 go build -o eth-client .

# 阶段3: 运行环境
FROM ubuntu:22.04 AS runtime

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libgmp10 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 创建应用目录
WORKDIR /app

# 复制C++库文件
COPY --from=cpp-builder /usr/local/lib /usr/local/lib
COPY --from=cpp-builder /usr/local/include /usr/local/include

# 复制Go应用
COPY --from=go-builder /workspace/demos-go/cmd/threshold-ecdsa-web/demo-runner ./demo-runner
COPY --from=go-builder /workspace/demos-go/cmd/eth-client/eth-client ./eth-client

# 复制配置文件
COPY --from=cpp-builder /workspace/demos-go/cmd/threshold-ecdsa-web/certs ./certs
COPY --from=cpp-builder /workspace/demos-go/cmd/threshold-ecdsa-web/config-*.yaml ./

# 设置环境变量
ENV LD_LIBRARY_PATH=/usr/local/lib

# 暴露端口
EXPOSE 7080 7081 7082 7083

# 创建启动脚本
RUN echo '#!/bin/bash\n\
echo "=== MPC项目Docker环境 ==="\n\
echo\n\
echo "可用的应用:"\n\
echo "1. demo-runner - threshold-ecdsa-web服务"\n\
echo "2. eth-client - ETH客户端"\n\
echo\n\
echo "使用方法:"\n\
echo "启动服务: ./demo-runner -index=0"\n\
echo "运行客户端: ./eth-client"\n\
echo\n\
echo "进入容器后可以运行这些命令"\n\
' > /app/start.sh && chmod +x /app/start.sh

# 设置默认命令
CMD ["/app/start.sh"]
