package securityanalysis

import (
	"regexp"
	"strings"
)

// SecurityAnalysis 执行安全分析，检测是否存在SQL注入和XSS攻击
func SecurityAnalysis(body string) bool {
	if detectSQLInjection(body) || detectXSS(body) || detectCSRF(body) ||
		detectRCE(body) || detectFileInclusion(body) || detectDirectoryTraversal(body) {
		return true
	}
	return false
}

// detectSQLInjection 复杂的SQL注入检测逻辑
func detectSQLInjection(body string) bool {
	// 常见SQL注入攻击模式
	sqlPatterns := []string{
		`(?i)select\s+.+\s+from`,              // SELECT * FROM users
		`(?i)union\s+select`,                  // UNION SELECT
		`(?i)or\s+1=1`,                        // OR 1=1
		`(?i)and\s+\d+=\d+`,                   // AND 1=1
		`(?i)or\s+'[^']*'='[^']*'`,            // OR 'x'='x'
		`(?i)insert\s+into\s+[^\s]+\s*\(.+\)`, // INSERT INTO users (id, name) VALUES
		`(?i)drop\s+table`,                    // DROP TABLE
		`(?i)update\s+[^\s]+\s+set`,           // UPDATE users SET
		`(?i)delete\s+from`,                   // DELETE FROM users
		`(?i)--`,                              // SQL注释符号 --
		`(?i)/\*.*\*/`,                        // SQL注释 /* ... */
		`(?i);`,                               // SQL分号
		`(?i)exec\s*\(`,                       // EXEC()函数调用
		`(?i)xp_cmdshell`,                     // SQL Server中的xp_cmdshell命令
	}

	// 逐一匹配正则表达式
	for _, pattern := range sqlPatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}

	// 检测单引号和双引号是否平衡
	if strings.Count(body, "'")%2 != 0 || strings.Count(body, "\"")%2 != 0 {
		return true
	}

	// 检测常见SQL关键字和操作符
	sqlKeywords := []string{
		"select", "insert", "update", "delete", "drop", "union", "alter",
		"exec", "xp_cmdshell", "from", "where", "or", "and", "--", ";", "/*", "*/",
	}

	for _, keyword := range sqlKeywords {
		if strings.Contains(strings.ToLower(body), keyword) {
			return true
		}
	}

	return false
}

// detectXSS 复杂的XSS攻击检测逻辑
func detectXSS(body string) bool {
	// 常见XSS攻击模式
	xssPatterns := []string{
		`(?i)<script[^>]*>.*?</script>`,              // <script>...</script>
		`(?i)javascript:[^\"']+`,                     // javascript:alert('XSS')
		`(?i)on[a-z]+\s*=\s*["']?[^\"']+["']?`,       // onmouseover="alert('XSS')"
		`(?i)<iframe[^>]*>.*?</iframe>`,              // <iframe>...</iframe>
		`(?i)<img\s+src\s*=\s*["'][^\"']+["']`,       // <img src="..." />
		`(?i)<[^>]+(src|href)\s*=\s*["'][^\"']*["']`, // <a href="..." />, <link href="...">
		`(?i)style\s*=\s*["'][^\"']+["']`,            // style="expression(...)"
		`(?i)<[^>]*>[^<]*(?i)</[^>]*>`,               // <tag>...</tag>
	}

	// 逐一匹配正则表达式
	for _, pattern := range xssPatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}

	// 检测是否包含危险的HTML标签或属性
	xssDangerousTags := []string{
		"script", "iframe", "object", "embed", "style", "link",
	}

	for _, tag := range xssDangerousTags {
		if strings.Contains(strings.ToLower(body), tag) {
			return true
		}
	}

	// 检测是否存在字符编码后的XSS攻击尝试
	decodedBody := strings.ToLower(body)
	decodedBody = strings.ReplaceAll(decodedBody, "%3C", "<")
	decodedBody = strings.ReplaceAll(decodedBody, "%3E", ">")
	decodedBody = strings.ReplaceAll(decodedBody, "%22", "\"")
	decodedBody = strings.ReplaceAll(decodedBody, "%27", "'")
	decodedBody = strings.ReplaceAll(decodedBody, "%28", "(")
	decodedBody = strings.ReplaceAll(decodedBody, "%29", ")")

	for _, pattern := range xssPatterns {
		if matched, _ := regexp.MatchString(pattern, decodedBody); matched {
			return true
		}
	}

	return false
}

// detectCSRF 跨站请求伪造检测逻辑
func detectCSRF(body string) bool {
	// 假设请求中必须包含合法的CSRF Token
	// 此处仅为简单示例，实际场景中应根据应用程序的实现方式调整
	tokenPattern := `(?i)csrf_token=\w+`
	if matched, _ := regexp.MatchString(tokenPattern, body); !matched {
		return true
	}

	// 检查Referer Header是否为可信任域名
	if !strings.Contains(body, "Referer: https://trusted-domain.com") {
		return true
	}

	return false
}

// detectRCE 远程代码执行检测逻辑
func detectRCE(body string) bool {
	rcePatterns := []string{
		`(?i)(\bexec\b|\bsystem\b|\bpopen\b|\beval\b)\(`, // 检测危险函数调用
		`(?i)base64_decode\(`,                            // 检测base64解码调用
		`(?i)<\?php`,                                     // 检测PHP代码执行
	}

	for _, pattern := range rcePatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}
	return false
}

// detectFileInclusion 文件包含攻击检测逻辑
func detectFileInclusion(body string) bool {
	fileInclusionPatterns := []string{
		`(?i)(\.\./|\.\.\\)`,         // 检测目录遍历符号
		`(?i)(/etc/passwd|/windows)`, // 检测敏感文件路径
	}

	for _, pattern := range fileInclusionPatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}
	return false
}

// detectDirectoryTraversal 目录遍历攻击检测逻辑
func detectDirectoryTraversal(body string) bool {
	traversalPatterns := []string{
		`(?i)\.\./\.\./`, // 检测目录遍历序列
	}

	for _, pattern := range traversalPatterns {
		if matched, _ := regexp.MatchString(pattern, body); matched {
			return true
		}
	}
	return false
}
