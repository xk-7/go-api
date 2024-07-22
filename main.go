package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	_ "go-api/docs" // 导入 Swagger 文档模块

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
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
// @Param destinationPath query string false "目标路径，默认值为 /home/sqray/cultures"
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

	destinationPath := c.Query("destinationPath")
	if destinationPath == "" {
		destinationPath = "/home/sqray/cultures" // 默认值
	}

	// 将 IP 列表拆分为字符串数组
	servers := strings.Split(serverIps, ",")

	// 执行构建命令并捕获输出日志
	var buildOutput bytes.Buffer
	cmd := exec.Command("sh", "-c", fmt.Sprintf("cd %s && %s", buildDir, buildCommand))
	cmd.Stdout = &buildOutput
	cmd.Stderr = &buildOutput
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("构建失败: %s", err.Error()), "log": buildOutput.String()})
		return
	}

	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}

		// 复制文件到服务器
		scpCommand := fmt.Sprintf("scp -r %s/* root@%s:%s", buildOutputDir, server, destinationPath)
		cmd = exec.Command("sh", "-c", scpCommand)
		var scpOutput bytes.Buffer
		cmd.Stdout = &scpOutput
		cmd.Stderr = &scpOutput
		if err := cmd.Run(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("文件复制到 %s 失败: %s", server, err.Error()), "log": scpOutput.String()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Files copied successfully", "log": buildOutput.String()})
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
// pauseContainer handles the API request to pause a Docker container
func pauseContainer(c *gin.Context) {
	containerName := c.Param("containerName")

	// Simulate pausing a container (replace with actual logic)
	// Example: cmd := exec.Command("docker", "pause", containerName)
	// err := cmd.Run()
	err := simulatePauseContainer(containerName)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to pause container"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Container paused successfully"})
}

// simulatePauseContainer simulates the logic for pausing a Docker container
func simulatePauseContainer(containerName string) error {
	// Simulated success
	return nil
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
// @Router /delete-container/{containerName} [delete]
func deleteContainer(c *gin.Context) {
	containerName := c.Param("containerName")
	if containerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供容器名参数"})
		return
	}

	cmd := exec.Command("docker", "rm", "-f", containerName)
	_, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除容器失败: %s", err.Error())})
		return
	}

	c.String(http.StatusOK, "Container deleted successfully")
}

// 获取容器日志
func getContainerLogs(c *gin.Context) {
	containerName := c.Param("containerName")
	serverIp := c.Query("serverIp")

	if serverIp == "" {
		serverIp = "localhost"
	}

	if containerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供容器名参数"})
		return
	}

	// SSH 命令：获取 Docker 容器日志并保存到临时文件
	var sshCommand string
	if serverIp == "localhost" {
		sshCommand = fmt.Sprintf("docker logs %s > /tmp/%s.log 2>&1", containerName, containerName)
	} else {
		sshCommand = fmt.Sprintf("docker logs %s > /tmp/%s.log 2>&1", containerName, containerName)
		// 使用 SSH 执行远程命令
		sshCommand = fmt.Sprintf("ssh root@%s \"%s\"", serverIp, sshCommand)
	}

	cmd := exec.Command("sh", "-c", sshCommand)
	err := cmd.Run()
	if err != nil {
		if strings.Contains(err.Error(), "No such container") {
			c.JSON(http.StatusNotFound, gin.H{"error": "容器不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("获取日志失败: %s", err.Error())})
		}
		return
	}

	// 返回日志文件的下载链接
	logFileURL := fmt.Sprintf("http://%s:8081/downloads/%s.log", serverIp, containerName)
	c.JSON(http.StatusOK, gin.H{"logFileURL": logFileURL})
}

// @Summary 获取服务器状态
// @Description 获取服务器的当前状态信息
// @Tags monitor
// @Accept  json
// @Produce  json
// @Success 200 {object} map[string]string "Server status"
// @Failure 500 {string} string "Internal server error"
// @Router /status [get]
func getStatus(c *gin.Context) {
	cmd := exec.Command("sh", "-c", "uptime")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get server status"})
		return
	}
	status := out.String()
	c.JSON(http.StatusOK, gin.H{"status": status})
}

// @Summary 管理防火墙规则
// @Description 添加、删除或列出防火墙规则
// @Tags firewall
// @Accept  json
// @Produce  json
// @Param action query string true "操作 (add/del/list)"
// @Param rule query string false "防火墙规则"
// @Success 200 {string} string "Firewall rule action completed"
// @Failure 400 {string} string "Invalid input"
// @Failure 500 {string} string "Internal server error"
// @Router /firewall [post]
func manageFirewall(c *gin.Context) {
	action := c.Query("action")
	rule := c.Query("rule")
	var cmd *exec.Cmd

	switch action {
	case "add":
		if rule == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide a firewall rule"})
			return
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ufw allow %s", rule))
	case "del":
		if rule == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please provide a firewall rule"})
			return
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ufw delete allow %s", rule))
	case "list":
		cmd = exec.Command("sh", "-c", "ufw status")
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action"})
		return
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to manage firewall"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": out.String()})
}

// @Summary 获取系统信息
// @Description 获取服务器的系统信息
// @Tags system
// @Accept  json
// @Produce  json
// @Success 200 {object} map[string]string "System information"
// @Failure 500 {string} string "Internal server error"
// @Router /system-info [get]
func getSystemInfo(c *gin.Context) {
	cmd := exec.Command("sh", "-c", "uname -a")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get system information"})
		return
	}
	systemInfo := out.String()
	c.JSON(http.StatusOK, gin.H{"system_info": systemInfo})
}

// @Summary 获取服务器磁盘使用情况
// @Description 获取服务器的磁盘使用情况
// @Tags system
// @Produce  json
// @Success 200 {string} string "Disk usage information"
// @Failure 500 {string} string "Internal server error"
// @Router /disk-usage [get]
func getDiskUsage(c *gin.Context) {
	cmd := exec.Command("df", "-h")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get disk usage"})
		return
	}

	c.String(http.StatusOK, out.String())
}

// @Summary 获取系统负载信息
// @Description 获取系统负载信息
// @Tags system
// @Produce  json
// @Success 200 {string} string "Load average information"
// @Failure 500 {string} string "Internal server error"
// @Router /load [get]
func getLoad(c *gin.Context) {
	cmd := exec.Command("uptime")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get system load"})
		return
	}

	c.String(http.StatusOK, out.String())
}

// @Summary 获取系统内存使用情况
// @Description 获取系统的内存使用情况
// @Tags system
// @Produce  json
// @Success 200 {string} string "Memory usage information"
// @Failure 500 {string} string "Internal server error"
// @Router /memory-usage [get]
func getMemoryUsage(c *gin.Context) {
	cmd := exec.Command("free", "-h")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get memory usage"})
		return
	}

	c.String(http.StatusOK, out.String())
}

// @Summary 获取系统日志
// @Description 获取系统日志文件
// @Tags system
// @Produce  json
// @Success 200 {string} string "System log content"
// @Failure 500 {string} string "Internal server error"
// @Router /logs [get]
func getLogs(c *gin.Context) {
	logFile := "/var/log/syslog" // 你可以更改为实际的日志文件路径
	data, err := os.ReadFile(logFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read log file"})
		return
	}

	c.String(http.StatusOK, string(data))
}

var sessions = make(map[string]*ssh.Client) // 用于存储每个用户的 SSH 客户端

// WebSocket 升级器
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// 登录接口
// @Summary 登录服务器并建立 WebSocket 连接
// @Description 使用用户名、密码和服务器IP进行登录
// @Tags server
// @Accept  json
// @Produce  json
// @Param username query string true "用户名"
// @Param passwd query string true "密码"
// @Param serverip query string true "服务器IP"
// @Success 200 {string} string "登录成功"
// @Failure 400 {string} string "无效的输入"
// @Failure 500 {string} string "内部服务器错误"
// @Router /serverlogin [post]
func serverLogin(c *gin.Context) {
	username := c.Query("username")
	passwd := c.Query("passwd")
	serverip := c.Query("serverip")

	if username == "" || passwd == "" || serverip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名、密码和服务器IP不能为空"})
		return
	}

	client, err := connectToServer(username, passwd, serverip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登录失败"})
		return
	}

	sessions[username] = client
	c.JSON(http.StatusOK, gin.H{"message": "登录成功"})
}

// 连接到服务器并返回 SSH 客户端
func connectToServer(username, passwd, serverip string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", serverip+":22", config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// @Summary WebSocket 终端接口
// @Description 建立 WebSocket 连接，用于与服务器交互
// @Tags terminal
// @Produce  json
// @Success 200 {string} string "WebSocket 连接成功"
// @Failure 500 {string} string "内部服务器错误"
// @Router /terminal [get]
func terminal(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名不能为空"})
		return
	}

	client, ok := sessions[username]
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户未登录"})
		return
	}

	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Error upgrading connection to WebSocket: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to establish WebSocket connection"})
		return
	}
	defer func() {
		if err := ws.Close(); err != nil {
			log.Printf("Error closing WebSocket connection: %v", err)
		}
		log.Println("WebSocket connection closed")
	}()

	session, err := client.NewSession()
	if err != nil {
		log.Printf("Error creating session: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to create session"))
		return
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Printf("Error creating stdin pipe: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to create stdin pipe"))
		return
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Printf("Error creating stdout pipe: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to create stdout pipe"))
		return
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		log.Printf("Error creating stderr pipe: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to create stderr pipe"))
		return
	}

	if err := session.Shell(); err != nil {
		log.Printf("Error starting shell: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to start shell"))
		return
	}

	// PONG handler to keep the connection alive
	ws.SetPongHandler(func(appData string) error {
		log.Println("Received PONG from client")
		return nil
	})
	// PING handler to respond to pings from the client
	ws.SetPingHandler(func(appData string) error {
		log.Println("Received PING from client")
		return ws.WriteMessage(websocket.PongMessage, nil)
	})

	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := stdout.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from stdout: %v", err)
				}
				break
			}
			if n > 0 {
				msg := string(buffer[:n])
				log.Printf("Sending data to client from stdout: %s", msg)
				if err := ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
					log.Printf("Error setting write deadline: %v", err)
					return
				}
				if err := ws.WriteMessage(websocket.TextMessage, buffer[:n]); err != nil {
					if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
						log.Println("WebSocket closed normally")
					} else {
						log.Printf("Error sending message to WebSocket: %v", err)
					}
					break
				}
			}
		}
	}()

	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := stderr.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from stderr: %v", err)
				}
				break
			}
			if n > 0 {
				msg := string(buffer[:n])
				log.Printf("Sending data to client from stderr: %s", msg)
				if err := ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
					log.Printf("Error setting write deadline: %v", err)
					return
				}
				if err := ws.WriteMessage(websocket.TextMessage, buffer[:n]); err != nil {
					if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
						log.Println("WebSocket closed normally")
					} else {
						log.Printf("Error sending message to WebSocket: %v", err)
					}
					break
				}
			}
		}
	}()

	go func() {
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					log.Println("WebSocket closed normally")
				} else {
					log.Printf("Error reading WebSocket message: %v", err)
				}
				break
			}
			log.Printf("Received message from WebSocket: %s", msg)
			if stdin != nil {
				if _, err := io.WriteString(stdin, string(msg)+"\n"); err != nil {
					log.Printf("Error writing to stdin: %v", err)
					break
				}
			} else {
				log.Println("stdin is not available.")
				break
			}
		}
	}()
}

func main() {
	r := gin.Default()

	// 设置静态文件目录
	r.Static("/css", "./css")
	r.Static("/js", "./js")
	r.StaticFile("/", "./index.html")

	// 添加 Swagger 路由
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	// 创建用户路由
	r.POST("/create-user/:username/:password", createUser)
	//服务器管理
	r.GET("/status", getStatus)
	r.POST("/firewall", manageFirewall)
	r.GET("/system-info", getSystemInfo)
	r.GET("/disk-usage", getDiskUsage)
	r.GET("/load", getLoad)
	r.GET("/memory-usage", getMemoryUsage)
	r.GET("/logs", getLogs)
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
	r.DELETE("/delete-container/:containerName", deleteContainer)
	// 获取容器日志路由
	r.GET("/logs/:containerName", getContainerLogs)
	// 提供下载文件的路由
	r.Static("/downloads", "/tmp")

	// 登录接口
	r.POST("/serverlogin", serverLogin)
	// WebSocket 终端接口
	r.GET("/terminal", terminal)

	// 启动服务器
	log.Println("Starting server on :8081")
	if err := r.Run(":8081"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
