package main

import (
	"firewall/api/router"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	router.Route(r)

	// 启动Gin服务器
	log.Println("WAF系统正在8080端口启动...")
	r.Run(":8080")
}
