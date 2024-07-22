// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/copy": {
            "get": {
                "description": "将构建文件复制到服务器",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "deployment"
                ],
                "summary": "部署文件到服务器",
                "parameters": [
                    {
                        "type": "string",
                        "description": "服务器 IP 列表，以逗号分隔",
                        "name": "serverIps",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "构建目录",
                        "name": "buildDir",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "构建命令",
                        "name": "buildCommand",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "构建输出目录",
                        "name": "buildOutputDir",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "目标路径，默认值为 /home/sqray/cultures",
                        "name": "destinationPath",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Files copied successfully",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Invalid input",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/create-user/{username}/{password}": {
            "post": {
                "description": "创建一个新的 Linux 用户",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "user"
                ],
                "summary": "创建 Linux 用户",
                "parameters": [
                    {
                        "type": "string",
                        "description": "用户名",
                        "name": "username",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "密码",
                        "name": "password",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "User created successfully",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Invalid input",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/delete-container/{containerName}": {
            "delete": {
                "description": "删除指定名称的 Docker 容器",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "docker"
                ],
                "summary": "删除 Docker 容器",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Docker 容器名",
                        "name": "containerName",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Container deleted successfully",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Invalid input",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/deploy-ceph": {
            "post": {
                "description": "部署Ceph集群，包括节点设置、Ceph配置、OSD部署等",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "ceph"
                ],
                "summary": "部署Ceph集群",
                "parameters": [
                    {
                        "description": "节点名称列表",
                        "name": "nodes",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    },
                    {
                        "description": "OSD磁盘列表",
                        "name": "osdDisks",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Ceph cluster deployed successfully",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/disk-usage": {
            "get": {
                "description": "获取服务器的磁盘使用情况",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "system"
                ],
                "summary": "获取服务器磁盘使用情况",
                "responses": {
                    "200": {
                        "description": "Disk usage information",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/firewall": {
            "post": {
                "description": "添加、删除或列出防火墙规则",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "firewall"
                ],
                "summary": "管理防火墙规则",
                "parameters": [
                    {
                        "type": "string",
                        "description": "操作 (add/del/list)",
                        "name": "action",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "防火墙规则",
                        "name": "rule",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Firewall rule action completed",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Invalid input",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/list-containers": {
            "get": {
                "description": "列出当前所有 Docker 容器的详细信息",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "docker"
                ],
                "summary": "列出所有 Docker 容器",
                "responses": {
                    "200": {
                        "description": "List of Docker containers",
                        "schema": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": true
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/load": {
            "get": {
                "description": "获取系统负载信息",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "system"
                ],
                "summary": "获取系统负载信息",
                "responses": {
                    "200": {
                        "description": "Load average information",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/login/{username}/{password}": {
            "post": {
                "description": "验证用户登录信息",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "authentication"
                ],
                "summary": "用户登录",
                "parameters": [
                    {
                        "type": "string",
                        "description": "用户名",
                        "name": "username",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "密码",
                        "name": "password",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Invalid input",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/logs": {
            "get": {
                "description": "获取系统日志文件",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "system"
                ],
                "summary": "获取系统日志",
                "responses": {
                    "200": {
                        "description": "System log content",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/memory-usage": {
            "get": {
                "description": "获取系统的内存使用情况",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "system"
                ],
                "summary": "获取系统内存使用情况",
                "responses": {
                    "200": {
                        "description": "Memory usage information",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/pause-container/{containerName}": {
            "post": {
                "description": "暂停指定名称的 Docker 容器",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "docker"
                ],
                "summary": "暂停 Docker 容器",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Docker 容器名",
                        "name": "containerName",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Container paused successfully",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Invalid input",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/serverlogin": {
            "post": {
                "description": "使用用户名、密码和服务器IP进行登录",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "server"
                ],
                "summary": "登录服务器并建立 WebSocket 连接",
                "parameters": [
                    {
                        "type": "string",
                        "description": "用户名",
                        "name": "username",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "密码",
                        "name": "passwd",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "服务器IP",
                        "name": "serverip",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "登录成功",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "无效的输入",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "内部服务器错误",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/status": {
            "get": {
                "description": "获取服务器的当前状态信息",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "monitor"
                ],
                "summary": "获取服务器状态",
                "responses": {
                    "200": {
                        "description": "Server status",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/system-info": {
            "get": {
                "description": "获取服务器的系统信息",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "system"
                ],
                "summary": "获取系统信息",
                "responses": {
                    "200": {
                        "description": "System information",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/terminal": {
            "get": {
                "description": "建立 WebSocket 连接，用于与服务器交互",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "terminal"
                ],
                "summary": "WebSocket 终端接口",
                "responses": {
                    "200": {
                        "description": "WebSocket 连接成功",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "内部服务器错误",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/update-docker/{version}/{containerName}": {
            "post": {
                "description": "在目标服务器上运行 Docker 容器",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "docker"
                ],
                "summary": "更新容器 API",
                "parameters": [
                    {
                        "type": "string",
                        "description": "版本号",
                        "name": "version",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Docker 容器名",
                        "name": "containerName",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "服务器 IP 列表，以逗号分隔",
                        "name": "serverIps",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Docker containers started successfully",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Invalid input",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
