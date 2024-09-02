package config

import (
	"firewall/internal/rulemanager"

	"github.com/spf13/viper"
)

var (
	CfgMysql *viper.Viper // mysql配置
	CfgRedis *viper.Viper // redis配置
)

// InitConfig 初始化配置文件
func InitConfig(filepath string) {
	viper.SetConfigFile(filepath)
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}

	CfgMysql = viper.Sub("mysql")
	if CfgMysql == nil {
		panic("config not found mysql.database")
	}

	CfgRedis = viper.Sub("redis")
	if CfgRedis == nil {
		panic("config not found redis.database")
	}
}

// 初始化日志记录器
func initializeLogger() {
	// 代码略...
}

func init() {
	// initDB()
	// initRedis()
	initializeLogger()
	rulemanager.LoadRules() // 从数据库加载规则
}
