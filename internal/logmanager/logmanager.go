package logmanager

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb *redis.Client
)

type LogEntry struct {
	ID      string
	Message string
	Time    time.Time
}

// LogEvent 记录安全事件日志
func LogEvent(id, message string) {
	entry := LogEntry{ID: id, Message: message, Time: time.Now()}
	logKey := "log:" + id

	rdb.LPush(context.Background(), logKey, entry)
}

// SyncLogsToDB 将Redis中的日志定期同步到MySQL中
func SyncLogsToDB() {
	// 从Redis中获取日志并存入MySQL
	// 代码略...
}
