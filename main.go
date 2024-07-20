package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	_ "go-api-server/docs" // 导入 Swagger 文档模块

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @Summary 创建 Linux 用户
// @Description 创建一个新的 Linux 用户
// @Tags user
// @Accept  json
// @Produce  json
// @Param username path string true "用户名"
// @Param password path string true "密码"
// @Success 200 {string} string "User created successfully"
// @Failure 400 {string} string "Invalid input"
// @Failure 500 {string} string "Internal server error"
// @Router /create-user/{username}/{password} [post]
func createUser(c *gin.Context) {
	username := c.Param("username")
	password := c.Param("password")
	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供用户名和密码参数"})
		return
	}

	// 创建用户的命令
	createUserCommand := fmt.Sprintf("useradd -s /bin/bash -m %s", username)
	cmd := exec.Command("sh", "-c", createUserCommand)
	_, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建用户失败: %s", err.Error())})
		return
	}

	// 设置用户密码的命令
	setPasswordCommand := fmt.Sprintf("echo '%s:%s' | chpasswd", username, password)
	cmd = exec.Command("sh", "-c", setPasswordCommand)
	_, err = cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("设置用户密码失败: %s", err.Error())})
		return
	}

	c.String(http.StatusOK, "User created successfully")
}

// @Summary 部署新版本到服务器
// @Description 将构建文件复制到服务器
// @Tags deployment
// @Accept  json
// @Produce  json
// @Param version path string true "版本号"
// @Param serverIps query string true "服务器 IP 列表，以逗号分隔"
// @Param buildDir query string false "构建目录"
// @Param buildCommand query string false "构建命令"
// @Success 200 {string} string "Files copied successfully"
// @Failure 400 {string} string "Invalid input"
// @Failure 500 {string} string "Internal server error"
// @Router /copy/{version} [post]
func copy(c *gin.Context) {
	version := c.Param("version")
	if version == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供版本号参数"})
		return
	}

	serverIps := c.Query("serverIps")
	if serverIps == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供服务器 IP 参数"})
		return
	}

	buildDir := c.Query("buildDir")
	if buildDir == "" {
		buildDir = "/root/dockerdata/jenkins/workspace/cell2.0" // 默认值
	}

	buildCommand := c.Query("buildCommand")
	if buildCommand == "" {
		buildCommand = "pnpm build:prod-https" // 默认值
	}

	// 将 IP 列表拆分为字符串数组
	servers := strings.Split(serverIps, ",")

	// 执行构建命令
	cmd := exec.Command("sh", "-c", fmt.Sprintf("cd %s && %s", buildDir, buildCommand))
	_, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("构建失败: %s", err.Error())})
		return
	}

	// 设置构建后的目录
	prodDir := fmt.Sprintf("%s/prod-https", buildDir)

	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}

		// 复制文件到服务器
		scpCommand := fmt.Sprintf("scp -r %s/* root@%s:/home/sqray/cultures", prodDir, server)
		cmd = exec.Command("sh", "-c", scpCommand)
		_, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("文件复制到 %s 失败: %s", server, err.Error())})
			return
		}
	}

	c.String(http.StatusOK, "Files copied successfully")
}

// @Summary 启动 Docker 容器
// @Description 在目标服务器上运行 Docker 容器
// @Tags docker
// @Accept  json
// @Produce  json
// @Param version path string true "版本号"
// @Param containerName path string true "Docker 容器名"
// @Param serverIps query string true "服务器 IP 列表，以逗号分隔"
// @Success 200 {string} string "Docker containers started successfully"
// @Failure 400 {string} string "Invalid input"
// @Failure 500 {string} string "Internal server error"
// @Router /start-docker/{version}/{containerName} [post]
func handleStartDocker(c *gin.Context) {
	version := c.Param("version")
	containerName := c.Param("containerName")
	if version == "" || containerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供版本号和容器名参数"})
		return
	}

	serverIps := c.Query("serverIps")
	if serverIps == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供服务器 IP 参数"})
		return
	}

	// 将 IP 列表拆分为字符串数组
	servers := strings.Split(serverIps, ",")

	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}

		// 在目标服务器上执行 Docker 命令
		sshCommand := fmt.Sprintf(`
			docker rm -f %s
			docker run --name=%s -itd --cpus=4 --memory=8g -p 7014:80 -v /root/apollo/%s/appsettings.json:/app/appsettings.json --restart=always harbor.sqray.com:5012/dev/cellculture:v2.0.%s
		`, containerName, containerName, containerName, version)
		cmd := exec.Command("ssh", fmt.Sprintf("root@%s", server), sshCommand)
		_, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Docker 容器在 %s 上运行失败: %s", server, err.Error())})
			return
		}
	}

	c.String(http.StatusOK, "Docker containers started successfully")
}

// 用户存储示例
var users = map[string]string{
	"admin": "password123", // 示例用户名和密码
}

// @Summary 用户登录
// @Description 验证用户登录信息
// @Tags authentication
// @Accept  json
// @Produce  json
// @Param username path string true "用户名"
// @Param password path string true "密码"
// @Success 200 {string} string "Login successful"
// @Failure 400 {string} string "Invalid input"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Internal server error"
// @Router /login/{username}/{password} [post]
func handleLogin(c *gin.Context) {
	username := c.Param("username")
	password := c.Param("password")

	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供用户名和密码"})
		return
	}

	// 简单的用户验证逻辑
	storedPassword, exists := users[username]
	if !exists || storedPassword != password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// @Summary 部署Ceph集群
// @Description 部署Ceph集群，包括节点设置、Ceph配置、OSD部署等
// @Tags ceph
// @Accept  json
// @Produce  json
// @Param nodes body []string true "节点名称列表"
// @Param nodeIPs body []string true "节点IP列表"
// @Param osdDisks body []string true "OSD磁盘列表"
// @Success 200 {string} string "Ceph cluster deployed successfully"
// @Failure 500 {string} string "Internal server error"
// @Router /deploy-ceph [post]
func deployCeph(c *gin.Context) {
	var requestData struct {
		Nodes    []string `json:"nodes"`
		NodeIPs  []string `json:"nodeIPs"`
		OSDDisks []string `json:"osdDisks"`
	}

	if err := c.ShouldBindJSON(&requestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	nodes := requestData.Nodes
	nodeIPs := requestData.NodeIPs
	osdDisks := requestData.OSDDisks
	fsid := "some-generated-uuid" // Generate or set your FSID here

	// 更新和安装依赖
	for _, node := range nodes {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'apt update && apt upgrade -y'", node))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update node %s: %s", node, string(output))})
			return
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'apt install -y ntp ssh ceph-deploy'", node))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to install dependencies on node %s: %s", node, string(output))})
			return
		}
	}

	// 设置主机名和hosts文件
	for i, node := range nodes {
		nodeIP := nodeIPs[i]
		cmd := exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'hostnamectl set-hostname %s'", node, node))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to set hostname on node %s: %s", node, string(output))})
			return
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'echo \"%s %s\" >> /etc/hosts'", node, nodeIP, node))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update /etc/hosts on node %s: %s", node, string(output))})
			return
		}
		for j, otherNode := range nodes {
			if i != j {
				otherIP := nodeIPs[j]
				cmd = exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'echo \"%s %s\" >> /etc/hosts'", node, otherIP, otherNode))
				if output, err := cmd.CombinedOutput(); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update /etc/hosts with %s on node %s: %s", otherNode, node, string(output))})
					return
				}
			}
		}
	}

	// 安装Ceph
	for _, node := range nodes {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'wget -q -O- \"https://download.ceph.com/keys/release.asc\" | apt-key add -'", node))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to add Ceph key on node %s: %s", node, string(output))})
			return
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'echo deb https://mirrors.aliyun.com/ceph/debian-18.2.0 $(lsb_release -sc) main | tee /etc/apt/sources.list.d/ceph.list'", node))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to add Ceph repository on node %s: %s", node, string(output))})
			return
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ssh root@%s 'apt update && apt install -y ceph'", node))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to install Ceph on node %s: %s", node, string(output))})
			return
		}
	}

	// 创建部署目录
	cmd := exec.Command("sh", "-c", "mkdir -p ~/ceph-cluster && cd ~/ceph-cluster")
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create deployment directory: %s", string(output))})
		return
	}

	// 创建Ceph配置文件和密钥
	cmd = exec.Command("sh", "-c", fmt.Sprintf("echo \"[global]\nfsid = %s\nmon initial members = %s\nmon host = %s\npublic network = 192.168.100.0/24\ncluster network = 192.168.100.0/24\nauth cluster required = cephx\nauth service required = cephx\nauth client required = cephx\nosd journal size = 1024\nosd pool default size = 3\nosd pool default min size = 2\nosd pool default pg num = 128\nosd pool default pgp num = 128\nosd crush chooseleaf type = 1\" > ceph.conf", fsid, strings.Join(nodes, ", "), strings.Join(nodeIPs, ", ")))
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create Ceph configuration file: %s", string(output))})
		return
	}

	// 部署monitor节点
	cmd = exec.Command("sh", "-c", "ceph-deploy mon create-initial")
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to deploy monitor node: %s", string(output))})
		return
	}

	// 部署OSD节点
	for _, node := range nodes {
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ceph-deploy disk zap %s %s", node, strings.Join(osdDisks, " ")))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to zap disks on node %s: %s", node, string(output))})
			return
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ceph-deploy osd create %s %s", node, strings.Join(osdDisks, " ")))
		if output, err := cmd.CombinedOutput(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create OSD on node %s: %s", node, string(output))})
			return
		}
	}

	// 部署Manager
	cmd = exec.Command("sh", "-c", fmt.Sprintf("ceph-deploy mgr create %s", strings.Join(nodes, " ")))
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to deploy Manager: %s", string(output))})
		return
	}

	// 检查集群状态
	cmd = exec.Command("sh", "-c", "ceph -s")
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to check Ceph cluster status: %s", string(output))})
		return
	}

	// 部署MDS（仅适用于CephFS）
	cmd = exec.Command("sh", "-c", fmt.Sprintf("ceph-deploy mds create %s", strings.Join(nodes, " ")))
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to deploy MDS: %s", string(output))})
		return
	}

	// 创建CephFS
	cmd = exec.Command("sh", "-c", "ceph osd pool create cephfs_data 128")
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create cephfs_data pool: %s", string(output))})
		return
	}
	cmd = exec.Command("sh", "-c", "ceph osd pool create cephfs_metadata 128")
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create cephfs_metadata pool: %s", string(output))})
		return
	}
	cmd = exec.Command("sh", "-c", "ceph fs new cephfs cephfs_metadata cephfs_data")
	if output, err := cmd.CombinedOutput(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create CephFS: %s", string(output))})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ceph cluster deployed successfully"})
}

func main() {
	r := gin.Default()

	// Swagger 文档路由
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// API 路由
	r.POST("/create-user/:username/:password", createUser)             // 创建用户路由
	r.POST("/copy/:version", copy)                                     // 文件部署路由
	r.POST("/start-docker/:version/:containerName", handleStartDocker) // Docker 启动路由
	r.POST("/login/:username/:password", handleLogin)                  // 登录路由
	r.POST("/deploy-ceph", deployCeph)

	// 监听 8081 端口
	r.Run(":8081")
}
