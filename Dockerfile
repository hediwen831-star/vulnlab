# VulnLab 容器镜像
#
# 官方 php 镜像默认不带 pdo_sqlite，需要手动装（这就是本 Dockerfile 存在的理由）。
# 本机已有 PHP 的话完全不需要用它 —— 见 README 的「零依赖启动」一节。

FROM php:7.3-cli-alpine

# 编译 pdo_sqlite 所需的最小依赖
RUN apk add --no-cache --virtual .build-deps $PHPIZE_DEPS sqlite-dev \
    && docker-php-ext-install pdo_sqlite \
    && apk del .build-deps

WORKDIR /app

# 只复制运行所需内容，PoC 与文档不进镜像
COPY html/ /app/html/

# 预建数据目录并放开权限（容器内以 root 跑，仅用于本地靶场）
RUN mkdir -p /app/html/data && chmod 777 /app/html/data

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD php -r "exit(@file_get_contents('http://127.0.0.1/index.php') ? 0 : 1);"

CMD ["php", "-S", "0.0.0.0:80", "-t", "/app/html"]
