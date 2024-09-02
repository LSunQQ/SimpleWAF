package rulemanager

import (
	"database/sql"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

var (
	rules      = make(map[string]Rule)
	rulesMutex = &sync.Mutex{}
	db         *sql.DB
)

type Rule struct {
	ID      string
	Pattern string
}

// LoadRules 从数据库加载规则到内存
func LoadRules() error {
	rows, err := db.Query("SELECT id, pattern FROM rules")
	if err != nil {
		return err
	}
	defer rows.Close()

	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	for rows.Next() {
		var rule Rule
		if err := rows.Scan(&rule.ID, &rule.Pattern); err != nil {
			return err
		}
		rules[rule.ID] = rule
	}
	return nil
}

// AddRule 添加新的安全规则到数据库
func AddRule(rule Rule) error {
	_, err := db.Exec("INSERT INTO rules (id, pattern) VALUES (?, ?)", rule.ID, rule.Pattern)
	if err == nil {
		rulesMutex.Lock()
		rules[rule.ID] = rule
		rulesMutex.Unlock()
	}
	return err
}
