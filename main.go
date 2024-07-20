package main

import (
	"bytes"
	"encoding/json"
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

// @Summary 部署文件到服务器
// @Description 将构建文件复制到服务器
// @Tags deployment
// @Accept  json
// @Produce  json
// @Param serverIps query string true "服务器 IP 列表，以逗号分隔"
// @Param buildDir query string false "构建目录"
// @Param buildCommand query string false "构建命令"
// @Param buildOutputDir query string false "构建输出目录"
// @Success 200 {string} string "Files copied successfully"
// @Failure 400 {string} string "Invalid input"
// @Failure 500 {string} string "Internal server error"
// @Router /copy [post]
func copy(c *gin.Context) {
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

	buildOutputDir := c.Query("buildOutputDir")
	if buildOutputDir == "" {
		buildOutputDir = fmt.Sprintf("%s/prod-https", buildDir) // 默认值
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

	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}

		// 复制文件到服务器
		scpCommand := fmt.Sprintf("scp -r %s/* root@%s:/home/sqray/cultures", buildOutputDir, server)
		cmd = exec.Command("sh", "-c", scpCommand)
		_, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("文件复制到 %s 失败: %s", server, err.Error())})
			return
		}
	}

	c.String(http.StatusOK, "Files copied successfully")
}

// @Summary 更新容器 API
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
// @Router /update-docker/{version}/{containerName} [post]
func handleUpdateDocker(c *gin.Context) {
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
// @Param osdDisks body []string true "OSD磁盘列表"
// @Success 200 {string} string "Ceph cluster deployed successfully"
// @Failure 500 {string} string "Internal server error"
// @Router /deploy-ceph [post]
func deployCeph(c *gin.Context) {
	var requestData struct {
		Nodes    []string `json:"nodes"`
		OSDDisks []string `json:"osdDisks"`
	}

	if err := c.ShouldBindJSON(&requestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	nodes := requestData.Nodes
	osdDisks := requestData.OSDDisks

	// 更新和安装 ceph-deploy
	updateAndInstallCephDeploy := "apt-get update && apt-get install -y ceph-deploy"
	if err := exec.Command("sh", "-c", updateAndInstallCephDeploy).Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update and install ceph-deploy"})
		return
	}

	// 创建集群目录
	clusterDir := "my-cluster"
	if err := exec.Command("sh", "-c", fmt.Sprintf("mkdir %s", clusterDir)).Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create cluster directory"})
		return
	}

	// 部署监视器和管理器
	monitorAndManager := fmt.Sprintf("cd %s && ceph-deploy new %s", clusterDir, strings.Join(nodes, " "))
	if err := exec.Command("sh", "-c", monitorAndManager).Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deploy monitor and manager"})
		return
	}

	// 配置 Ceph
	configCeph := fmt.Sprintf("cd %s && ceph-deploy install %s && ceph-deploy mon create-initial", clusterDir, strings.Join(nodes, " "))
	if err := exec.Command("sh", "-c", configCeph).Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to configure Ceph"})
		return
	}

	// 部署 OSD
	for i, node := range nodes {
		deployOSD := fmt.Sprintf("cd %s && ceph-deploy osd create --data %s %s", clusterDir, osdDisks[i], node)
		if err := exec.Command("sh", "-c", deployOSD).Run(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to deploy OSD on node %s", node)})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ceph cluster deployed successfully"})
}

// @Summary 列出所有 Docker 容器
// @Description 列出当前所有 Docker 容器的详细信息
// @Tags docker
// @Accept  json
// @Produce  json
// @Success 200 {object} []map[string]interface{} "List of Docker containers"
// @Failure 500 {string} string "Internal server error"
// @Router /list-containers [get]
func listContainers(c *gin.Context) {
	cmd := exec.Command("docker", "ps", "--format", "{{json .}}")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list Docker containers"})
		return
	}

	lines := strings.Split(out.String(), "\n")
	var containers []map[string]interface{}
	for _, line := range lines {
		if line == "" {
			continue
		}

		var container map[string]interface{}
		if err := json.Unmarshal([]byte(line), &container); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse Docker container output"})
			return
		}

		containers = append(containers, container)
	}

	c.JSON(http.StatusOK, containers)
}

// @Summary 暂停 Docker 容器
// @Description 暂停指定名称的 Docker 容器
// @Tags docker
// @Accept  json
// @Produce  json
// @Param containerName path string true "Docker 容器名"
// @Success 200 {string} string "Container paused successfully"
// @Failure 400 {string} string "Invalid input"
// @Failure 500 {string} string "Internal server error"
// @Router /pause-container/{containerName} [post]
func pauseContainer(c *gin.Context) {
	containerName := c.Param("containerName")
	if containerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供容器名参数"})
		return
	}

	cmd := exec.Command("docker", "pause", containerName)
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to pause container %s: %s", containerName, err.Error())})
		return
	}

	c.String(http.StatusOK, "Container paused successfully")
}

// @Summary 删除 Docker 容器
// @Description 删除指定名称的 Docker 容器
// @Tags docker
// @Accept  json
// @Produce  json
// @Param containerName path string true "Docker 容器名"
// @Success 200 {string} string "Container deleted successfully"
// @Failure 400 {string} string "Invalid input"
// @Failure 500 {string} string "Internal server error"
// @Router /delete-container/{containerName} [post]
func deleteContainer(c *gin.Context) {
	containerName := c.Param("containerName")
	if containerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供容器名参数"})
		return
	}

	cmd := exec.Command("docker", "rm", "-f", containerName)
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete container %s: %s", containerName, err.Error())})
		return
	}

	c.String(http.StatusOK, "Container deleted successfully")
}

func main() {
	r := gin.Default()

	// 添加 Swagger 路由
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// 创建用户路由
	r.POST("/create-user/:username/:password", createUser)

	// 部署文件路由
	r.POST("/copy", copy)

	// 更新容器 API 路由
	r.POST("/update-docker/:version/:containerName", handleUpdateDocker)

	// 用户登录路由
	r.POST("/login/:username/:password", handleLogin)

	// 部署 Ceph 路由
	r.POST("/deploy-ceph", deployCeph)

	// 管理容器的 API 路由
	r.GET("/list-containers", listContainers)
	r.POST("/pause-container/:containerName", pauseContainer)
	r.POST("/delete-container/:containerName", deleteContainer)

	r.Run(":8081")
}
