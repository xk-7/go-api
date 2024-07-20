# Go API Server

这是一个使用 Go 编写的 API 服务器，提供了用户管理、文件部署、Docker 容器管理和 Ceph 集群部署等功能。

## 功能

- **用户管理**
  - 创建 Linux 用户
  - 用户登录

- **文件部署**
  - 将构建文件复制到远程服务器

- **Docker 容器管理**
  - 启动 Docker 容器

- **Ceph 集群部署**
  - 部署 Ceph 集群，包括节点设置、Ceph 配置、OSD 部署等

## 依赖

- [Gin](https://github.com/gin-gonic/gin) - Go 的 HTTP Web 框架
- [Swaggo](https://github.com/swaggo/swag) - 用于生成 Swagger 文档
- 其他依赖项请查看 `go.mod` 文件

## 安装

1. 克隆本仓库：

    ```bash
    git clone https://github.com/yourusername/go-api-server.git
    cd go-api-server
    ```

2. 安装依赖：

    ```bash
    go mod tidy
    ```

3. 生成 Swagger 文档：

    ```bash
    swag init
    ```

## 运行

使用以下命令启动服务器：

```bash
go run main.go

