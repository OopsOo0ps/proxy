// 规则文档解析（routing.Rules 的 YAML 形态）。
//
// config 是全仓唯一的 yaml 依赖属主：规则文档的解析与前置校验收敛在此，
// routing / ruleset 只消费纯结构（零 yaml）。文件格式与 configs/example-rules.yaml
// 保持一致：顶层 default（可省）+ rules 列表；match 条目的合法性在解析期
// 校验（错误带行号），编译语义与 routing 引擎同源。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"gopkg.in/yaml.v3"
)

// Rules 是规则文档的解析载体（结构与 routing.Rules 一致）。
type Rules struct {
	// Default 是文档指定的默认动作；为空时由调用方决定。
	Default *ruleDefault `yaml:"default"`
	// Rules 按书写顺序匹配，先命中者生效。
	Rules []ruleEntry `yaml:"rules"`
}

// ruleDefault 是文档顶层 default 键（解析期校验动作写法）。
type ruleDefault struct {
	action core.RouteAction
}

func (d *ruleDefault) UnmarshalYAML(node *yaml.Node) error {
	action, err := routing.ParseAction(node.Value)
	if err != nil {
		return err
	}
	d.action = action
	return nil
}

// ruleEntry 是文档中的一条规则（解析期即校验动作与 match 条目）。
type ruleEntry struct {
	action core.RouteAction
	Match  []string
}

// UnmarshalYAML 解析规则条目，并对未知字段报错（错误带文档行号）。
func (r *ruleEntry) UnmarshalYAML(node *yaml.Node) error {
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
	action, err := routing.ParseAction(raw.Action)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	if len(raw.Match) == 0 {
		return fmt.Errorf("line %d: rule.match must not be empty", node.Line)
	}
	// 解析阶段即校验条目合法性，让错误信息带上规则文件行号。
	for _, entry := range raw.Match {
		if err := routing.CheckEntry(entry); err != nil {
			return fmt.Errorf("line %d: %w", node.Line, err)
		}
	}
	r.action = action
	r.Match = raw.Match
	return nil
}

// ParseRules 解析规则文件内容（严格模式：未知字段报错）。
// 返回 routing 引擎可用的纯结构；文档为空时返回空规则集。
func ParseRules(data []byte) (*routing.Rules, error) {
	var doc Rules
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return &routing.Rules{}, nil
		}
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	out := &routing.Rules{Rules: make([]routing.Rule, 0, len(doc.Rules))}
	if doc.Default != nil {
		def := doc.Default.action
		out.Default = &def
	}
	for _, r := range doc.Rules {
		out.Rules = append(out.Rules, routing.Rule{Action: r.action, Match: r.Match})
	}
	return out, nil
}
