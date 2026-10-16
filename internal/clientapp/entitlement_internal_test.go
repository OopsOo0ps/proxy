package clientapp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
)

// entitlementStore 写入一份 entitlement 文件（与账户库同一格式）并返回以
// fixed 为当前时钟的只读 Store（订阅判定完全确定，无真实时间依赖）。
func entitlementStore(t *testing.T, fixed time.Time, users string) (*accounts.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "entitlements.json")
	doc := `{"version":1,"users":[` + users + `]}` + "\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := accounts.LoadReadOnly(path)
	if err != nil {
		t.Fatalf("accounts.LoadReadOnly: %v", err)
	}
	st.Now = func() time.Time { return fixed }
	return st, path
}

// entitlementEntry 构造单个用户的 entitlement 文件行（口令只存摘要，镜像
// I3 纪律）；sub 为空 = 无订阅。
func entitlementEntry(name, password, sub string) string {
	sum256 := sha256.Sum256([]byte(password))
	sum224 := sha256.Sum224([]byte(password))
	entry := fmt.Sprintf(`{"username":%q,"password_sha256":%q,"password_sha224":%q,"status":"active"`,
		name, hex.EncodeToString(sum256[:]), hex.EncodeToString(sum224[:]))
	if sub != "" {
		entry += `,"subscription":` + sub
	}
	return entry + `}`
}

// —— 复合认证器（设计书 §3.1 客户端行：静态 ∧ 订阅）——

func TestGatedAuthComposite(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	expiredSub := `{"expires_at":"2026-01-01T00:00:00Z","granted_at":"2025-01-01T00:00:00Z"}`
	validSub := `{"expires_at":"2099-01-01T00:00:00Z","granted_at":"2025-01-01T00:00:00Z"}`
	users := entitlementEntry("alice", "pw-alice", expiredSub) + "," +
		entitlementEntry("dave", "pw-dave", validSub)
	entitlement, _ := entitlementStore(t, fixed, users)

	static, err := auth.NewStore([]auth.User{
		{Username: "alice", Password: "pw-alice"},
		{Username: "carol", Password: "pw-carol"}, // 有静态凭据、不在 entitlement
		{Username: "dave", Password: "pw-dave"},
	})
	if err != nil {
		t.Fatal(err)
	}

	comp := gatedAuth{static: static, gate: entitlement.Gate(true)}
	cases := []struct {
		name       string
		user, pass string
		want       bool
	}{
		{"static ok + subscription valid", "dave", "pw-dave", true},
		{"static ok + subscription expired", "alice", "pw-alice", false},
		{"static ok + not in entitlement", "carol", "pw-carol", false},
		{"static bad", "dave", "wrong", false},
		{"unknown user", "eve", "pw-eve", false},
	}
	for _, tc := range cases {
		if got := comp.Authenticate(tc.user, tc.pass); got != tc.want {
			t.Errorf("%s: Authenticate(%q) = %v, want %v", tc.name, tc.user, got, tc.want)
		}
	}

	// 无静态维度（防御路径）：entitlement 单独判定，不静默放行。
	gateOnly := gatedAuth{gate: entitlement.Gate(true)}
	if !gateOnly.Authenticate("dave", "pw-dave") {
		t.Error("gate-only: valid subscription must pass")
	}
	if gateOnly.Authenticate("alice", "pw-alice") {
		t.Error("gate-only: expired subscription must be denied")
	}
}

// —— liveView.Auth() 的 nil 纪律（消费方以接口 == nil 判定「不校验」）——

func TestLiveViewAuthNilSemantics(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	validSub := `{"expires_at":"2099-01-01T00:00:00Z","granted_at":"2025-01-01T00:00:00Z"}`
	entitlement, _ := entitlementStore(t, fixed, entitlementEntry("dave", "pw-dave", validSub))
	static, err := auth.NewStore([]auth.User{{Username: "dave", Password: "pw-dave"}})
	if err != nil {
		t.Fatal(err)
	}

	// 双缺省：必须返回真正的 nil 接口（消费方以接口 == nil 判定「不校验」；
	// 变量的静态类型就是 core.Authenticator——nil 指针装进接口不会 == nil）。
	none := liveView{}.Auth()
	if none != nil {
		t.Fatal("liveView without auth and gate must return a nil interface")
	}

	// 仅静态凭据：现状行为（非 nil，可用）。
	if staticOnly := (liveView{auth: static}).Auth(); staticOnly == nil || !staticOnly.Authenticate("dave", "pw-dave") {
		t.Fatal("auth-only liveView must expose the static store")
	}

	// 静态 ∧ 门禁：复合体两维都参与判定。
	comp := (liveView{auth: static, gate: entitlement.Gate(true)}).Auth()
	if comp == nil {
		t.Fatal("static + gate liveView must return a composite authenticator")
	}
	if !comp.Authenticate("dave", "pw-dave") {
		t.Fatal("composite must allow a valid subscription")
	}

	// 钉在过期快照上的视图拒绝同一凭据（生效边界 = 新连接 / 新一代快照）。
	expired, _ := entitlementStore(t, fixed, entitlementEntry("dave", "pw-dave",
		`{"expires_at":"2026-01-01T00:00:00Z","granted_at":"2025-01-01T00:00:00Z"}`))
	if (liveView{auth: static, gate: expired.Gate(true)}).Auth().Authenticate("dave", "pw-dave") {
		t.Fatal("composite with the expired view must deny the same credentials")
	}
}

// —— buildEntitlement：门禁激活条件与 fail-closed（§3.3 运行期行）——

func TestBuildEntitlementActivation(t *testing.T) {
	var live atomic.Pointer[Runtime]
	b := newBuilder(BuildOptions{}, &live)

	// gate 缺省 = 门禁不活跃，返回 nil（行为与现状逐字一致）。
	gate, err := b.buildEntitlement(&config.Config{})
	if err != nil || gate != nil {
		t.Fatalf("absent gate: gate=%v err=%v, want nil/nil", gate, err)
	}

	// gate.enabled 但无 accounts：组装失败（防御式拦一道，不静默降级）。
	if _, err := b.buildEntitlement(&config.Config{Gate: &config.Gate{Enabled: true}}); err == nil {
		t.Fatal("gate.enabled without accounts must fail to assemble")
	}

	// gate.enabled + 文件缺失：组装失败（启动期 = 拒绝启动；重载期 = 保留旧配置）。
	bad := &config.Config{
		Gate:     &config.Gate{Enabled: true},
		Accounts: &config.Accounts{File: filepath.Join(t.TempDir(), "missing.json")},
	}
	if _, err := b.buildEntitlement(bad); err == nil {
		t.Fatal("gate.enabled with missing entitlement file must fail to assemble")
	}

	// gate.enabled + 有效文件：构建门禁视图且 on = true（无订阅即拒绝）。
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	_, path := entitlementStore(t, fixed, entitlementEntry("dave", "pw-dave", ""))
	ok := &config.Config{
		Gate:     &config.Gate{Enabled: true},
		Accounts: &config.Accounts{File: path},
	}
	gate, err = b.buildEntitlement(ok)
	if err != nil {
		t.Fatalf("buildEntitlement: %v", err)
	}
	if gate == nil {
		t.Fatal("gate.enabled with a valid file must build the gate view")
	}
	if gate.Authenticate("dave", "pw-dave") {
		t.Fatal("gate is on: a user without a subscription must be denied")
	}
}
