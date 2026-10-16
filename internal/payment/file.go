package payment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
)

// 订单文件格式（版本化 JSON，单写者；与 accounts.json 相互独立的持久化文件，
// 设计书 §1.1 两个聚合各自独立落盘）：
//
//	{
//	  "version": 1,
//	  "orders": [
//	    {
//	      "order_id": "O20261015120000<16 位十六进制>",
//	      "username": "alice",
//	      "amount_cents": 3000,
//	      "status": "applied",
//	      "trade_no": "<网关交易号，paid/applied 必有>",
//	      "gmt_payment": "yyyy-MM-dd HH:mm:ss（网关原文，仅审计）",
//	      "created_at": "RFC3339",
//	      "expires_at": "RFC3339",
//	      "applied_at": "RFC3339（未落地时省略）"
//	    }
//	  ]
//	}
//
// 严格加载：未知字段 / 未知版本 / 尾随数据 / 非法状态组合 / 重复订单号一律
// 报错（fail-closed，设计书 §1.1 I5）；文件缺失 = 空库（首次运行合法：还没
// 有任何订单，与 accounts 的「缺失即拒启动」不同——订单库允许从零生长）。
// 原子持久化：写同目录临时文件 + fsync + rename；任意时刻进程退出，要么旧
// 文件完好（rename 前），要么新文件完整（rename 后）；遗留的临时文件不被
// 加载路径读取，下次落盘即清理。
const fileVersion = 1

// fileFormat 是订单文件的信封。
type fileFormat struct {
	Version int         `json:"version"`
	Orders  []fileOrder `json:"orders"`
}

// fileOrder 是订单文件的行记录（导出模型 Order 的持久化形态：时刻以 RFC3339
// 字符串表达，未落地时 applied_at 整体省略）。
type fileOrder struct {
	OrderID     string      `json:"order_id"`
	Username    string      `json:"username"`
	AmountCents int64       `json:"amount_cents"`
	Status      OrderStatus `json:"status"`
	TradeNo     string      `json:"trade_no,omitempty"`
	GmtPayment  string      `json:"gmt_payment,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	AppliedAt   *time.Time  `json:"applied_at,omitempty"`
}

// Open 严格加载订单文件并返回可变 Service（变更即原子落盘）。文件缺失 = 空
// 库（首次运行合法）；损坏 / 格式漂移一律报错（fail-closed，§1.1 I5）。
// store 必须非空（订阅延长是落地的唯一出口），period_days 与 price_cents
// 必须为正（固定单一档位，构造期 fail-fast）。
func Open(path string, store *accounts.Store, periodDays int, priceCents int64) (*Service, error) {
	if store == nil {
		return nil, errors.New("payment: accounts store must not be nil")
	}
	if periodDays <= 0 {
		return nil, fmt.Errorf("payment: period_days must be positive, got %d", periodDays)
	}
	if priceCents <= 0 {
		return nil, fmt.Errorf("payment: price_cents must be positive, got %d", priceCents)
	}
	orders, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Service{
		Now:        time.Now,
		accounts:   store,
		periodDays: periodDays,
		priceCents: priceCents,
		orders:     make(map[string]Order, len(orders)),
		path:       path,
	}
	for _, o := range orders {
		s.orders[o.OrderID] = o
		s.ids = append(s.ids, o.OrderID)
	}
	return s, nil
}

// loadFile 严格加载订单文件并返回订单行（保持文件顺序）。文件缺失返回空库
// （首次运行合法）；其余一律报错。
func loadFile(path string) ([]Order, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // 首次运行：还没有订单文件 = 空库（合法）
		}
		return nil, fmt.Errorf("payment: load %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f fileFormat
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("payment: load %s: %w", path, err)
	}
	// 严格性补充：文件必须是恰好一个 JSON 值，拒绝尾随数据。
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("payment: load %s: unexpected trailing data", path)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("payment: load %s: unsupported version %d (want %d)", path, f.Version, fileVersion)
	}

	orders := make([]Order, 0, len(f.Orders))
	seen := make(map[string]bool, len(f.Orders))
	for i, fo := range f.Orders {
		o, err := fo.order()
		if err != nil {
			return nil, fmt.Errorf("payment: load %s: orders[%d]: %w", path, i, err)
		}
		if seen[o.OrderID] {
			return nil, fmt.Errorf("payment: load %s: orders[%d]: duplicate order_id %q", path, i, o.OrderID)
		}
		seen[o.OrderID] = true
		orders = append(orders, o)
	}
	return orders, nil
}

// order 校验并转换为领域形态（文件形态 → 领域形态；状态值与状态机字段的
// 组合形状在此把关：pending/closed 不携带支付事实，paid/applied 必有幂等键
// trade_no，applied 必有落地时刻）。
func (f fileOrder) order() (Order, error) {
	if f.OrderID == "" {
		return Order{}, fmt.Errorf("%w: order_id must not be empty", ErrInvalidOrder)
	}
	if f.Username == "" {
		return Order{}, fmt.Errorf("%w: order %s: username must not be empty", ErrInvalidOrder, f.OrderID)
	}
	if f.AmountCents <= 0 {
		return Order{}, fmt.Errorf("%w: order %s: amount_cents must be positive, got %d", ErrInvalidOrder, f.OrderID, f.AmountCents)
	}
	if f.CreatedAt.IsZero() || f.ExpiresAt.IsZero() {
		return Order{}, fmt.Errorf("%w: order %s: created_at and expires_at must be set", ErrInvalidOrder, f.OrderID)
	}
	switch f.Status {
	case OrderPending, OrderClosed:
		if f.TradeNo != "" || f.GmtPayment != "" || f.AppliedAt != nil {
			return Order{}, fmt.Errorf("%w: order %s: %s order must not carry payment facts", ErrInvalidOrder, f.OrderID, f.Status)
		}
	case OrderPaid:
		if f.TradeNo == "" {
			return Order{}, fmt.Errorf("%w: order %s: paid order must carry trade_no", ErrInvalidOrder, f.OrderID)
		}
		if f.AppliedAt != nil {
			return Order{}, fmt.Errorf("%w: order %s: paid order must not carry applied_at", ErrInvalidOrder, f.OrderID)
		}
	case OrderApplied:
		if f.TradeNo == "" || f.AppliedAt == nil {
			return Order{}, fmt.Errorf("%w: order %s: applied order must carry trade_no and applied_at", ErrInvalidOrder, f.OrderID)
		}
	default:
		return Order{}, fmt.Errorf("%w: order %s: unknown status %q", ErrInvalidOrder, f.OrderID, f.Status)
	}
	o := Order{
		OrderID:     f.OrderID,
		Username:    f.Username,
		AmountCents: f.AmountCents,
		Status:      f.Status,
		TradeNo:     f.TradeNo,
		GmtPayment:  f.GmtPayment,
		CreatedAt:   f.CreatedAt,
		ExpiresAt:   f.ExpiresAt,
	}
	if f.AppliedAt != nil {
		o.AppliedAt = *f.AppliedAt
	}
	return o, nil
}

// saveFile 把订单行原子写入 path：序列化 → 同目录临时文件 → fsync → rename
// （同目录保证同一文件系统内原子替换；镜像 accounts 的落盘纪律）。
func saveFile(path string, orders []Order) error {
	f := fileFormat{Version: fileVersion, Orders: make([]fileOrder, 0, len(orders))}
	for _, o := range orders {
		f.Orders = append(f.Orders, fileOrderOf(o))
	}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	data = append(data, '\n')

	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // rename 成功后无此文件；失败路径清理半写临时文件

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// rename 落盘后同步目录项：保证掉电后 rename 本身不丢（文件内容已 fsync）。
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

// fileOrderOf 转换为持久化形态（领域形态 → 文件形态；未落地时 applied_at
// 整体省略）。
func fileOrderOf(o Order) fileOrder {
	fo := fileOrder{
		OrderID:     o.OrderID,
		Username:    o.Username,
		AmountCents: o.AmountCents,
		Status:      o.Status,
		TradeNo:     o.TradeNo,
		GmtPayment:  o.GmtPayment,
		CreatedAt:   o.CreatedAt,
		ExpiresAt:   o.ExpiresAt,
	}
	if !o.AppliedAt.IsZero() {
		fo.AppliedAt = &o.AppliedAt
	}
	return fo
}
