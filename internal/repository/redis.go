package repository

import (
	"firewall/config"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Redis 绑定数据库配置
type Redis struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Database int    `mapstructure:"database"`
}

var defaultRedis *redis.Client

// InitRedis 初始化redis
func InitRedis() {
	var redisCfg Redis
	config.CfgRedis.Unmarshal(&redisCfg)

	rc := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", redisCfg.Host, redisCfg.Port),
		Username: redisCfg.User,
		Password: redisCfg.Password,
		DB:       redisCfg.Database,
	})
	defaultRedis = rc
}

// GetRedisClient 获取redis客户端
func GetRedisClient() *redis.Client {
	if defaultRedis == nil {
		InitRedis()
	}
	return defaultRedis
}
