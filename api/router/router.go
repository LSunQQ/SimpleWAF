package router

import (
	"firewall/internal/rulemanager"
	"firewall/internal/traffichandler"

	"github.com/gin-gonic/gin"
)

func Route(r *gin.Engine) {
	// 定义路由
	r.POST("/traffic", traffichandler.TrafficHandler)
	r.POST("/rules", func(c *gin.Context) {
		var rule rulemanager.Rule
		if err := c.ShouldBindJSON(&rule); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		if err := rulemanager.AddRule(rule); err != nil {
			c.JSON(500, gin.H{"error": "无法添加规则"})
		} else {
			c.JSON(201, gin.H{"status": "规则添加成功"})
		}
	})
	r.GET("/logs", func(c *gin.Context) {
		// 返回日志信息的处理逻辑
	})
}
