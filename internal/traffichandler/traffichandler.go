package traffichandler

import (
	"firewall/internal/logmanager"
	"firewall/internal/securityanalysis"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// TrafficHandler 处理传入的流量请求
func TrafficHandler(c *gin.Context) {
	// 读取请求体进行分析
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, gin.H{"error": "内部服务器错误"})
		return
	}
	bodyString := string(bodyBytes)

	// 调用安全分析模块
	if securityanalysis.SecurityAnalysis(bodyString) {
		logmanager.LogEvent(c.ClientIP(), "检测到SQL注入")
		c.JSON(403, gin.H{"error": "检测到恶意请求"})
		return
	}

	// 转发请求到后端服务
	target := "http://backend_service" // 替换为实际的后端服务地址
	req, err := http.NewRequest(c.Request.Method, target+c.Request.RequestURI, io.NopCloser(io.Reader(c.Request.Body)))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 复制请求头
	for name, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Set(name, value)
		}
	}

	// 执行请求并获取响应
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	// 返回响应
	for name, values := range resp.Header {
		for _, value := range values {
			c.Writer.Header().Add(name, value)
		}
	}
	c.Writer.WriteHeader(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}
