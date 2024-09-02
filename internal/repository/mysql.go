package repository

import (
	"firewall/config"
	"fmt"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var defaultMysql *gorm.DB

// MySQL 绑定数据库配置
type MySQL struct {
	Host         string `mapstructure:"host"`
	Port         string `mapstructure:"port"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	Database     string `mapstructure:"database"`
	CharSet      string `mapstructure:"charset"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
}

// InitMySQL 初始化MySQL
func InitMySQL() {
	var mysqlCfg MySQL
	config.CfgMysql.Unmarshal(&mysqlCfg)

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&parseTime=True",
		mysqlCfg.User,
		mysqlCfg.Password,
		mysqlCfg.Host,
		mysqlCfg.Port,
		mysqlCfg.Database,
		mysqlCfg.CharSet)

	// 连接mysql
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("can not connect to mysql database", err.Error())
	}

	// 自动迁移表
	// db.AutoMigrate(&msg{})
	defaultMysql = db

	log.Println("mysql connect success")
}

// GetMySQL 获取redis客户端
func GetMySQL() *gorm.DB {
	if defaultMysql == nil {
		InitMySQL()
	}
	return defaultMysql
}
