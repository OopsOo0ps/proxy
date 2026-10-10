package routing

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Rules 是规则文件的解析结果。
type Rules struct {
	// Default 是规则文件指定的默认动作；为空时由调用方决定。
	Default *Action `yaml:"default"`
	// Rules 按书写顺序匹配，先命中者生效。
	Rules []Rule `yaml:"rules"`
}

// Rule 是一条分流规则。
type Rule struct {
	Action Action
	Match  []string
}

// UnmarshalYAML 解析规则条目，并对未知字段报错。
func (r *Rule) UnmarshalYAML(node *yaml.Node) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if key != "action" && key != "match" {
			return fmt.Errorf("line %d: unknown field %q in routing rule", node.Content[i].Line, key)
		}
	}
	var raw struct {
		Action string   `yaml:"action"`
		Match  []string `yaml:"match"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	action, err := ParseAction(raw.Action)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	if len(raw.Match) == 0 {
		return fmt.Errorf("line %d: rule.match must not be empty", node.Line)
	}
	// 解析阶段即校验条目合法性，让错误信息带上规则文件行号。
	for _, entry := range raw.Match {
		if _, err := compileMatcher(entry); err != nil {
			return fmt.Errorf("line %d: %w", node.Line, err)
		}
	}
	r.Action = action
	r.Match = raw.Match
	return nil
}

// LoadRulesFile 读取并解析规则文件；文件为空返回空规则集。
func LoadRulesFile(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	rules, err := ParseRules(data)
	if err != nil {
		return nil, fmt.Errorf("rules file %s: %w", path, err)
	}
	return rules, nil
}

// ParseRules 解析规则文件内容（严格模式：未知字段报错）。
func ParseRules(data []byte) (*Rules, error) {
	var rules Rules
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&rules); err != nil {
		if errors.Is(err, io.EOF) {
			return &Rules{}, nil
		}
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &rules, nil
}
