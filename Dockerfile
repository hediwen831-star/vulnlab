# VulnLab 容器镜像
#
# 官方 php 镜像默认不带 pdo_sqlite，需要手动装（这就是本 Dockerfile 存在的理由）。
# 本机已有 PHP 的话完全不需要用它 —— 见 README 的「零依赖启动」一节。

# PHP 8.1（LTS）
#
# 为什么不用 7.3：它已 EOL 多年，官方镜像随时可能被清理。
# 8.1 是长期支持版本，而且靶场 CI 就跑在 7.4 / 8.1 矩阵上 ——
# 兼容性有验证（靶场代码本身兼容 7.2+，本档位用的是最基础的语法）。
FROM php:8.1-cli-alpine

# 编译 pdo_sqlite 所需的最小依赖
RUN apk add --no-cache --virtual .build-deps $PHPIZE_DEPS sqlite-dev \
    && docker-php-ext-install pdo_sqlite \
    && apk del .build-deps

WORKDIR /app

# 只复制运行所需内容，PoC 与文档不进镜像
COPY html/ /app/html/

# 预建数据目录并放开权限（容器内以 root 跑，仅用于本地靶场）
RUN mkdir -p /app/html/data && chmod 777 /app/html/data

# SSRF 场景的目标地址。
#
# 这里给的是「本机 php -S 双端口」部署方式的默认值；
# docker-compose 会用环境变量覆盖成 http://vulnlab-internal ——
# 因为容器内的 127.0.0.1 指向容器自己，不是另一个容器。
ENV VULNLAB_INTERNAL_BASE=http://127.0.0.1:8090

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD php -r "exit(@file_get_contents('http://127.0.0.1/index.php') ? 0 : 1);"

CMD ["php", "-S", "0.0.0.0:80", "-t", "/app/html"]
