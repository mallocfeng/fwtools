package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

type syncResult struct {
	Inserted int `json:"inserted"`
	Updated  int `json:"updated"`
	Skipped  int `json:"skipped"`
}

type AppUser struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Email        string    `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	Blocked      bool      `gorm:"not null;default:false" json:"blocked"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Plan struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name         string    `gorm:"size:100;not null" json:"name"`
	InboundID    int       `gorm:"not null;index" json:"inboundId"`
	TrafficGB    int       `gorm:"not null" json:"trafficGB"`
	DurationDays int       `gorm:"not null" json:"durationDays"`
	PriceCents   int64     `gorm:"not null" json:"priceCents"`
	Currency     string    `gorm:"size:8;not null;default:USD" json:"currency"`
	Status       string    `gorm:"size:20;not null;default:ACTIVE" json:"status"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Order struct {
	ID          uint64     `gorm:"primaryKey;autoIncrement" json:"id"`
	OrderNo     string     `gorm:"size:64;uniqueIndex;not null" json:"orderNo"`
	UserID      uint64     `gorm:"not null;index" json:"userId"`
	PlanID      uint64     `gorm:"not null;index" json:"planId"`
	InboundID   int        `gorm:"not null;index;default:1" json:"inboundId"`
	AmountCents int64      `gorm:"not null" json:"amountCents"`
	Currency    string     `gorm:"size:8;not null" json:"currency"`
	Status      string     `gorm:"size:20;not null;default:PENDING" json:"status"`
	PaidAt      *time.Time `gorm:"default:null" json:"paidAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

type ServiceRecord struct {
	ID              uint64    `gorm:"primaryKey;autoIncrement;column:id" json:"id"`
	UserID          uint64    `gorm:"column:user_id;not null;index" json:"userID"`
	UserEmail       string    `gorm:"-" json:"userEmail"`
	UserBlocked     bool      `gorm:"-" json:"userBlocked"`
	OrderID         uint64    `gorm:"column:order_id;not null;uniqueIndex" json:"orderID"`
	PlanID          uint64    `gorm:"column:plan_id;not null;index" json:"planID"`
	InboundID       int       `gorm:"column:inbound_id;not null;index" json:"inboundID"`
	NodeRemark      string    `gorm:"-" json:"nodeRemark"`
	ClientEmail     string    `gorm:"column:client_email;size:255;uniqueIndex;not null" json:"clientEmail"`
	ClientID        string    `gorm:"column:client_uuid;size:64" json:"clientID"`
	ClientPassword  string    `gorm:"column:client_password;size:128" json:"-"`
	ClientSubID     string    `gorm:"column:client_sub_id;size:64;uniqueIndex;not null" json:"clientSubID"`
	TotalBytes      int64     `gorm:"column:total_bytes" json:"totalBytes"`
	ExpiryTimeMs    int64     `gorm:"column:expiry_time_ms" json:"expiryTimeMs"`
	SubscriptionURL string    `gorm:"-" json:"subscriptionURL"`
	Enabled         bool      `gorm:"-" json:"enabled"`
	Online          bool      `gorm:"-" json:"online"`
	Status          string    `gorm:"column:status;size:20;not null;default:DONE" json:"status"`
	CreatedAt       time.Time `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt       time.Time `gorm:"column:updated_at" json:"updatedAt"`
}

func (ServiceRecord) TableName() string { return "user_service_records" }

type App struct {
	db  *gorm.DB
	cfg Config
}

type Config struct {
	Port          string
	SessionSecret string
	DBHost        string
	DBPort        string
	DBUser        string
	DBPassword    string
	DBName        string
	PanelBaseURL  string
	PanelUser     string
	PanelPass     string
	SubBaseURL    string
}

type panelMsg struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

type panelInbound struct {
	ID       int    `json:"id"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Settings string `json:"settings"`
}

type panelClient struct {
	ID         string `json:"id"`
	Password   string `json:"password"`
	Email      string `json:"email"`
	SubID      string `json:"subId"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
	Enable     bool   `json:"enable"`
	Comment    string `json:"comment"`
	Security   string `json:"security"`
	Flow       string `json:"flow"`
	LimitIP    int    `json:"limitIp"`
}

var (
	upperRe   = regexp.MustCompile(`[A-Z]`)
	lowerRe   = regexp.MustCompile(`[a-z]`)
	digitRe   = regexp.MustCompile(`[0-9]`)
	specialRe = regexp.MustCompile(`[^A-Za-z0-9]`)
)

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

func loadConfig() Config {
	return Config{
		Port:          getenv("APP_PORT", "8090"),
		SessionSecret: getenv("APP_SESSION_SECRET", "change-me-please"),
		DBHost:        getenv("DB_HOST", ""),
		DBPort:        getenv("DB_PORT", "1433"),
		DBUser:        getenv("DB_USER", ""),
		DBPassword:    getenv("DB_PASSWORD", ""),
		DBName:        getenv("DB_NAME", ""),
		PanelBaseURL:  strings.TrimRight(getenv("PANEL_BASE_URL", "http://127.0.0.1:2053"), "/"),
		PanelUser:     getenv("PANEL_ADMIN_USER", "admin"),
		PanelPass:     getenv("PANEL_ADMIN_PASS", "admin"),
		SubBaseURL:    getenv("PANEL_SUB_BASE_URL", "http://127.0.0.1:2096/sub/"),
	}
}

func (c Config) dsn() string {
	return fmt.Sprintf("sqlserver://%s:%s@%s:%s?database=%s&encrypt=disable&connection+timeout=5", c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName)
}

func main() {
	cfg := loadConfig()
	if cfg.DBHost == "" || cfg.DBUser == "" || cfg.DBPassword == "" || cfg.DBName == "" {
		log.Fatal("DB_HOST/DB_USER/DB_PASSWORD/DB_NAME are required")
	}

	db, err := gorm.Open(sqlserver.Open(cfg.dsn()), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&AppUser{}, &Plan{}, &Order{}, &ServiceRecord{}); err != nil {
		log.Fatal(err)
	}

	app := &App{db: db, cfg: cfg}
	if err := app.ensureDefaultPlans(); err != nil {
		log.Printf("ensureDefaultPlans on startup failed: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.SetFuncMap(template.FuncMap{})
	r.LoadHTMLGlob("templates/*.html")

	store := cookie.NewStore([]byte(cfg.SessionSecret))
	store.Options(sessions.Options{Path: "/", MaxAge: 86400 * 7, HttpOnly: true})
	r.Use(sessions.Sessions("fw-user", store))

	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusTemporaryRedirect, "/user/login") })
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	r.GET("/user/register", func(c *gin.Context) { c.HTML(http.StatusOK, "user_register.html", nil) })
	r.GET("/user/login", func(c *gin.Context) { c.HTML(http.StatusOK, "user_login.html", nil) })
	r.GET("/user/dashboard", app.userAuth(), func(c *gin.Context) { c.HTML(http.StatusOK, "user_dashboard.html", nil) })

	r.GET("/admin/login", func(c *gin.Context) { c.HTML(http.StatusOK, "admin_login.html", nil) })
	r.GET("/admin/dashboard", app.adminAuth(), func(c *gin.Context) { c.HTML(http.StatusOK, "admin_dashboard.html", nil) })

	r.POST("/api/user/register", app.userRegister)
	r.POST("/api/user/login", app.userLogin)
	r.POST("/api/user/logout", app.userAuth(), app.userLogout)
	r.GET("/api/user/me", app.userAuth(), app.userMe)
	r.GET("/api/user/plans", app.userAuth(), app.userPlans)
	r.GET("/api/user/inbounds", app.userAuth(), app.userInbounds)
	r.GET("/api/user/orders", app.userAuth(), app.userOrders)
	r.POST("/api/user/orders", app.userAuth(), app.userCreateOrder)
	r.DELETE("/api/user/orders/:id", app.userAuth(), app.userDeleteOrder)
	r.POST("/api/user/orders/:id/pay", app.userAuth(), app.userPayOrder)
	r.GET("/api/user/services", app.userAuth(), app.userServices)

	r.POST("/api/admin/login", app.adminLogin)
	r.GET("/api/admin/services", app.adminAuth(), app.adminServices)
	r.POST("/api/admin/services/sync", app.adminAuth(), app.adminSyncServices)
	r.POST("/api/admin/users/:id/block", app.adminAuth(), app.adminBlockUser)
	r.POST("/api/admin/users/:id/unblock", app.adminAuth(), app.adminUnblockUser)
	r.POST("/api/admin/services/:id/disable", app.adminAuth(), app.adminDisable)
	r.POST("/api/admin/services/:id/enable", app.adminAuth(), app.adminEnable)
	r.POST("/api/admin/services/:id/delete", app.adminAuth(), app.adminDelete)

	log.Printf("fw-user-service running on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}

func (a *App) ensureDefaultPlans() error {
	defaultPlans := []Plan{
		{Name: "10G 30天", TrafficGB: 10, DurationDays: 30, PriceCents: 1000, Currency: "CNY", Status: "ACTIVE", InboundID: 1},
		{Name: "20G 90天", TrafficGB: 20, DurationDays: 90, PriceCents: 1500, Currency: "CNY", Status: "ACTIVE", InboundID: 1},
		{Name: "30G 365天", TrafficGB: 30, DurationDays: 365, PriceCents: 2000, Currency: "CNY", Status: "ACTIVE", InboundID: 1},
	}
	return a.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Plan{}).Where("1=1").Update("status", "INACTIVE").Error; err != nil {
			return err
		}
		for _, p := range defaultPlans {
			current := Plan{}
			err := tx.Where("name = ?", p.Name).Limit(1).Find(&current).Error
			if err == nil && current.ID == 0 {
				err = gorm.ErrRecordNotFound
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if err := tx.Create(&p).Error; err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			current.TrafficGB = p.TrafficGB
			current.DurationDays = p.DurationDays
			current.PriceCents = p.PriceCents
			current.Currency = p.Currency
			current.Status = "ACTIVE"
			if err := tx.Save(&current).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *App) userAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		s := sessions.Default(c)
		if s.Get("uid") == nil {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"success": false, "msg": "unauthorized"})
			} else {
				c.Redirect(http.StatusTemporaryRedirect, "/user/login")
			}
			c.Abort()
			return
		}
		c.Next()
	}
}

func (a *App) adminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		s := sessions.Default(c)
		if s.Get("admin") != true {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"success": false, "msg": "unauthorized"})
			} else {
				c.Redirect(http.StatusTemporaryRedirect, "/admin/login")
			}
			c.Abort()
			return
		}
		c.Next()
	}
}

func (a *App) userRegister(c *gin.Context) {
	var req struct{ Email, Password string }
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if msg := validateRegisterInput(req.Email, req.Password); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": msg})
		return
	}
	exists := int64(0)
	if err := a.db.Model(&AppUser{}).Where("email = ?", req.Email).Count(&exists).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	if exists > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "该邮箱已注册，请直接登录"})
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	u := AppUser{Email: req.Email, PasswordHash: string(h)}
	if err := a.db.Create(&u).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	s := sessions.Default(c)
	s.Set("uid", u.ID)
	s.Set("uemail", u.Email)
	s.Save()
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func validateRegisterInput(email, password string) string {
	if email == "" {
		return "邮箱不能为空"
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || !strings.Contains(addr.Address, "@") {
		return "请输入有效的邮箱地址"
	}
	if len(password) < 8 {
		return "密码至少 8 位"
	}
	if !upperRe.MatchString(password) || !lowerRe.MatchString(password) {
		return "密码需包含大小写字母"
	}
	if !digitRe.MatchString(password) {
		return "密码需包含数字"
	}
	if !specialRe.MatchString(password) {
		return "密码需包含特殊字符"
	}
	return ""
}

func (a *App) userLogin(c *gin.Context) {
	var req struct{ Email, Password string }
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	u := AppUser{}
	if err := a.db.Where("email = ?", req.Email).First(&u).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "msg": "invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "msg": "invalid credentials"})
		return
	}
	s := sessions.Default(c)
	s.Set("uid", u.ID)
	s.Set("uemail", u.Email)
	s.Save()
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) userLogout(c *gin.Context) {
	s := sessions.Default(c)
	s.Delete("uid")
	s.Delete("uemail")
	s.Save()
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) userMe(c *gin.Context) {
	uid := a.uid(c)
	u := AppUser{}
	if err := a.db.Select("id", "email", "blocked").Where("id = ?", uid).First(&u).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "msg": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": gin.H{"id": u.ID, "email": u.Email, "blocked": u.Blocked}})
}

func (a *App) uid(c *gin.Context) uint64 {
	s := sessions.Default(c)
	v := s.Get("uid")
	switch t := v.(type) {
	case uint64:
		return t
	case int:
		return uint64(t)
	case int64:
		return uint64(t)
	case float64:
		return uint64(t)
	default:
		return 0
	}
}

func (a *App) userPlans(c *gin.Context) {
	if err := a.ensureDefaultPlans(); err != nil {
		log.Printf("ensureDefaultPlans before userPlans failed: %v", err)
	}
	plans := make([]Plan, 0)
	a.db.Where("status = ?", "ACTIVE").Order("id asc").Find(&plans)
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": plans})
}

func (a *App) userInbounds(c *gin.Context) {
	cli, err := a.panelClient(a.cfg.PanelUser, a.cfg.PanelPass)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	inbounds, err := a.panelListInbounds(cli)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	type opt struct {
		ID     int    `json:"id"`
		Remark string `json:"remark"`
	}
	out := make([]opt, 0, len(inbounds))
	for _, ib := range inbounds {
		remark := strings.TrimSpace(ib.Remark)
		if remark == "" {
			remark = fmt.Sprintf("节点-%d", ib.ID)
		}
		out = append(out, opt{ID: ib.ID, Remark: remark})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": out})
}

func (a *App) userCreateOrder(c *gin.Context) {
	uid := a.uid(c)
	if blocked, err := a.isUserBlocked(uid); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	} else if blocked {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "msg": "账号因违反使用规范已被禁用，无法购买新节点"})
		return
	}
	var req struct {
		PlanID    uint64 `json:"planId"`
		InboundID int    `json:"inboundId"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	p := Plan{}
	if err := a.db.Where("id = ? and status = ?", req.PlanID, "ACTIVE").First(&p).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid plan"})
		return
	}
	if req.InboundID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "请选择节点"})
		return
	}
	if _, ok := a.panelInboundRemark(req.InboundID); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "所选节点不存在或已删除"})
		return
	}
	o := Order{OrderNo: fmt.Sprintf("FW-%d-%d", uid, time.Now().UnixNano()), UserID: uid, PlanID: p.ID, InboundID: req.InboundID, AmountCents: p.PriceCents, Currency: p.Currency, Status: "PENDING"}
	if err := a.db.Create(&o).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": o})
}

func (a *App) userOrders(c *gin.Context) {
	uid := a.uid(c)
	rows := make([]Order, 0)
	if err := a.db.Where("user_id = ? and status = ?", uid, "PENDING").Order("id desc").Find(&rows).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": rows})
}

func randStr(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (a *App) userPayOrder(c *gin.Context) {
	uid := a.uid(c)
	if blocked, err := a.isUserBlocked(uid); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	} else if blocked {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "msg": "账号因违反使用规范已被禁用，无法开通新节点"})
		return
	}
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	o := Order{}
	if err := a.db.Where("id = ? and user_id = ?", id, uid).First(&o).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "order not found"})
		return
	}
	if o.Status == "PAID" {
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}
	p := Plan{}
	if err := a.db.Where("id = ? and status = ?", o.PlanID, "ACTIVE").First(&p).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "plan not found"})
		return
	}
	targetInbound := o.InboundID
	if targetInbound <= 0 {
		targetInbound = p.InboundID
	}
	if _, ok := a.panelInboundRemark(targetInbound); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "所选节点不存在或已删除"})
		return
	}

	clientID := randStr(8) + "-" + randStr(4) + "-" + randStr(4) + "-" + randStr(4) + "-" + randStr(12)
	clientEmail := fmt.Sprintf("u%d-o%d@fw.local", uid, o.ID)
	subID := randStr(16)
	clientPass := randStr(36)
	expiry := time.Now().Add(time.Duration(p.DurationDays) * 24 * time.Hour).UnixMilli()
	if p.DurationDays <= 0 {
		expiry = 0
	}
	cl := panelClient{ID: clientID, Email: clientEmail, SubID: subID, Password: clientPass, TotalGB: int64(p.TrafficGB) * 1024 * 1024 * 1024, ExpiryTime: expiry, Enable: true, Comment: "order:" + o.OrderNo, Security: "auto"}

	if err := a.panelAddClient(targetInbound, cl); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	now := time.Now()
	o.Status = "PAID"
	o.PaidAt = &now
	a.db.Save(&o)

	subURL := strings.TrimRight(a.cfg.SubBaseURL, "/") + "/" + subID
	rec := ServiceRecord{
		UserID:         uid,
		OrderID:        o.ID,
		PlanID:         p.ID,
		InboundID:      targetInbound,
		ClientEmail:    clientEmail,
		ClientID:       clientID,
		ClientPassword: clientPass,
		ClientSubID:    subID,
		TotalBytes:     cl.TotalGB,
		ExpiryTimeMs:   cl.ExpiryTime,
		Status:         "DONE",
	}
	a.db.Create(&rec)
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": gin.H{"subscriptionUrl": subURL}})
}

func (a *App) userDeleteOrder(c *gin.Context) {
	uid := a.uid(c)
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	o := Order{}
	if err := a.db.Where("id = ? and user_id = ?", id, uid).First(&o).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "order not found"})
		return
	}
	if strings.EqualFold(o.Status, "PAID") {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "paid order cannot be deleted"})
		return
	}
	if err := a.db.Delete(&o).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) userServices(c *gin.Context) {
	uid := a.uid(c)
	// Keep user-side view consistent with panel changes (including manual deletes in 3x-ui).
	if _, err := a.syncFromPanel(a.cfg.PanelUser, a.cfg.PanelPass); err != nil {
		log.Printf("syncFromPanel before userServices failed: %v", err)
	}
	rows := make([]ServiceRecord, 0)
	a.db.Where("user_id = ? and status = ?", uid, "DONE").Order("id desc").Find(&rows)
	a.fillSubscriptionURL(rows)
	a.fillNodeRemark(rows)
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": rows})
}

func (a *App) adminLogin(c *gin.Context) {
	var req struct{ Username, Password string }
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "username/password required"})
		return
	}
	if err := a.panelLogin(req.Username, req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "msg": err.Error()})
		return
	}
	s := sessions.Default(c)
	s.Set("admin", true)
	s.Set("admin_user", req.Username)
	s.Set("admin_pass", req.Password)
	s.Save()
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) adminCreds(c *gin.Context) (string, string) {
	s := sessions.Default(c)
	u, _ := s.Get("admin_user").(string)
	p, _ := s.Get("admin_pass").(string)
	if strings.TrimSpace(u) == "" || strings.TrimSpace(p) == "" {
		return a.cfg.PanelUser, a.cfg.PanelPass
	}
	return u, p
}

func (a *App) adminServices(c *gin.Context) {
	u, p := a.adminCreds(c)
	_, _ = a.syncFromPanel(u, p)
	rows := make([]ServiceRecord, 0)
	a.db.Order("id desc").Find(&rows)
	a.fillSubscriptionURL(rows)
	a.fillUserProfile(rows)
	a.fillNodeRemark(rows)
	onlineSet, _ := a.panelOnlineSet(u, p)
	a.fillStatus(rows, onlineSet)
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": rows})
}

func (a *App) adminSyncServices(c *gin.Context) {
	u, p := a.adminCreds(c)
	res, err := a.syncFromPanel(u, p)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": res})
}

func (a *App) fillSubscriptionURL(rows []ServiceRecord) {
	base := strings.TrimRight(a.cfg.SubBaseURL, "/")
	for i := range rows {
		if rows[i].ClientSubID == "" {
			continue
		}
		rows[i].SubscriptionURL = base + "/" + rows[i].ClientSubID
	}
}

func (a *App) fillStatus(rows []ServiceRecord, onlineSet map[string]bool) {
	for i := range rows {
		rows[i].Enabled = strings.EqualFold(rows[i].Status, "DONE")
		rows[i].Online = onlineSet[strings.ToLower(strings.TrimSpace(rows[i].ClientEmail))]
	}
}

func (a *App) fillUserProfile(rows []ServiceRecord) {
	uidSet := make(map[uint64]struct{})
	for i := range rows {
		if rows[i].UserID > 0 {
			uidSet[rows[i].UserID] = struct{}{}
		}
	}
	if len(uidSet) == 0 {
		return
	}
	ids := make([]uint64, 0, len(uidSet))
	for id := range uidSet {
		ids = append(ids, id)
	}
	users := make([]AppUser, 0)
	if err := a.db.Select("id", "email", "blocked").Where("id IN ?", ids).Find(&users).Error; err != nil {
		return
	}
	userMap := make(map[uint64]AppUser, len(users))
	for _, u := range users {
		userMap[u.ID] = u
	}
	for i := range rows {
		if u, ok := userMap[rows[i].UserID]; ok {
			rows[i].UserEmail = u.Email
			rows[i].UserBlocked = u.Blocked
		}
	}
}

func (a *App) fillNodeRemark(rows []ServiceRecord) {
	inboundMap, err := a.panelInboundRemarkMap()
	if err != nil {
		return
	}
	for i := range rows {
		rows[i].NodeRemark = inboundMap[rows[i].InboundID]
	}
}

func (a *App) panelInboundRemark(inboundID int) (string, bool) {
	m, err := a.panelInboundRemarkMap()
	if err != nil {
		return "", false
	}
	v, ok := m[inboundID]
	return v, ok
}

func (a *App) panelInboundRemarkMap() (map[int]string, error) {
	cli, err := a.panelClient(a.cfg.PanelUser, a.cfg.PanelPass)
	if err != nil {
		return nil, err
	}
	inbounds, err := a.panelListInbounds(cli)
	if err != nil {
		return nil, err
	}
	out := make(map[int]string, len(inbounds))
	for _, ib := range inbounds {
		remark := strings.TrimSpace(ib.Remark)
		if remark == "" {
			remark = fmt.Sprintf("节点-%d", ib.ID)
		}
		out[ib.ID] = remark
	}
	return out, nil
}

func (a *App) isUserBlocked(uid uint64) (bool, error) {
	if uid == 0 {
		return false, nil
	}
	u := AppUser{}
	if err := a.db.Select("id", "blocked").Where("id = ?", uid).First(&u).Error; err != nil {
		return false, err
	}
	return u.Blocked, nil
}

func (a *App) adminBlockUser(c *gin.Context) {
	uid, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if uid == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid user id"})
		return
	}
	if err := a.db.Where("id = ?", uid).First(&AppUser{}).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "user not found"})
		return
	}
	if err := a.db.Model(&AppUser{}).Where("id = ?", uid).Update("blocked", true).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	u, p := a.adminCreds(c)
	rows := make([]ServiceRecord, 0)
	a.db.Where("user_id = ?", uid).Find(&rows)
	disabled := 0
	for i := range rows {
		if err := a.panelSetClientEnable(u, p, rows[i].ClientEmail, false); err != nil {
			continue
		}
		rows[i].Status = "DISABLED"
		a.db.Save(&rows[i])
		disabled++
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "obj": gin.H{"disabledServices": disabled}})
}

func (a *App) adminUnblockUser(c *gin.Context) {
	uid, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if uid == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid user id"})
		return
	}
	if err := a.db.Model(&AppUser{}).Where("id = ?", uid).Update("blocked", false).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) syncFromPanel(username, password string) (syncResult, error) {
	out := syncResult{}
	cli, err := a.panelClient(username, password)
	if err != nil {
		return out, err
	}
	inbounds, err := a.panelListInbounds(cli)
	if err != nil {
		return out, err
	}
	seenEmail := make(map[string]struct{})
	seenSubID := make(map[string]struct{})
	hasParseErr := false
	for _, ib := range inbounds {
		var raw struct {
			Clients []panelClient `json:"clients"`
		}
		if err := json.Unmarshal([]byte(ib.Settings), &raw); err != nil {
			out.Skipped++
			hasParseErr = true
			continue
		}
		for _, pc := range raw.Clients {
			email := strings.TrimSpace(pc.Email)
			subID := strings.TrimSpace(pc.SubID)
			if email == "" || subID == "" {
				out.Skipped++
				continue
			}
			seenEmail[strings.ToLower(email)] = struct{}{}
			seenSubID[strings.ToLower(subID)] = struct{}{}
			status := "DONE"
			if !pc.Enable {
				status = "DISABLED"
			}
			rec := ServiceRecord{}
			err := a.db.Where("client_email = ? OR client_sub_id = ?", email, subID).First(&rec).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return out, err
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				rec = ServiceRecord{
					UserID:         0,
					OrderID:        uint64(time.Now().UnixNano()) + uint64(rand.Intn(1000)),
					PlanID:         0,
					InboundID:      ib.ID,
					ClientEmail:    email,
					ClientID:       pc.ID,
					ClientPassword: pc.Password,
					ClientSubID:    subID,
					TotalBytes:     pc.TotalGB,
					ExpiryTimeMs:   pc.ExpiryTime,
					Status:         status,
				}
				if err := a.db.Create(&rec).Error; err != nil {
					return out, err
				}
				out.Inserted++
				continue
			}
			rec.InboundID = ib.ID
			rec.ClientEmail = email
			rec.ClientID = pc.ID
			rec.ClientPassword = pc.Password
			rec.ClientSubID = subID
			rec.TotalBytes = pc.TotalGB
			rec.ExpiryTimeMs = pc.ExpiryTime
			rec.Status = status
			if err := a.db.Save(&rec).Error; err != nil {
				return out, err
			}
			out.Updated++
		}
	}
	// If we parsed all inbound settings successfully, remove local records that
	// no longer exist in panel. This keeps refresh results consistent with 3x-ui.
	if !hasParseErr {
		rows := make([]ServiceRecord, 0)
		if err := a.db.Find(&rows).Error; err != nil {
			return out, err
		}
		for _, rec := range rows {
			_, hasEmail := seenEmail[strings.ToLower(strings.TrimSpace(rec.ClientEmail))]
			_, hasSubID := seenSubID[strings.ToLower(strings.TrimSpace(rec.ClientSubID))]
			if hasEmail || hasSubID {
				continue
			}
			if err := a.db.Delete(&ServiceRecord{}, rec.ID).Error; err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func (a *App) adminDisable(c *gin.Context) { a.adminSetEnable(c, false) }
func (a *App) adminEnable(c *gin.Context)  { a.adminSetEnable(c, true) }

func (a *App) adminSetEnable(c *gin.Context, enable bool) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	rec := ServiceRecord{}
	if err := a.db.Where("id = ?", id).First(&rec).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "record not found"})
		return
	}
	u, p := a.adminCreds(c)
	if err := a.panelSetClientEnable(u, p, rec.ClientEmail, enable); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	if enable {
		rec.Status = "DONE"
	} else {
		rec.Status = "DISABLED"
	}
	a.db.Save(&rec)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) adminDelete(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	rec := ServiceRecord{}
	if err := a.db.Where("id = ?", id).First(&rec).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "msg": "record not found"})
		return
	}
	u, p := a.adminCreds(c)
	if err := a.panelDeleteClient(u, p, rec.InboundID, rec.ClientEmail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": err.Error()})
		return
	}
	a.db.Delete(&rec)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) panelClient(username, password string) (*http.Client, error) {
	jar, _ := cookiejar.New(nil)
	cli := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	resp, err := cli.PostForm(a.cfg.PanelBaseURL+"/login", form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := panelMsg{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	if !m.Success {
		if m.Msg == "" {
			m.Msg = "panel login failed"
		}
		return nil, errors.New(m.Msg)
	}
	return cli, nil
}

func (a *App) panelLogin(username, password string) error {
	_, err := a.panelClient(username, password)
	return err
}

func (a *App) panelDoJSON(cli *http.Client, method, path string, form url.Values) (*panelMsg, error) {
	var req *http.Request
	var err error
	full := a.cfg.PanelBaseURL + path
	if method == http.MethodGet {
		req, err = http.NewRequest(method, full, nil)
	} else {
		req, err = http.NewRequest(method, full, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if err != nil {
		return nil, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := &panelMsg{}
	if err := json.Unmarshal(body, m); err != nil {
		return nil, err
	}
	return m, nil
}

func (a *App) panelAddClient(inboundID int, client panelClient) error {
	cli, err := a.panelClient(a.cfg.PanelUser, a.cfg.PanelPass)
	if err != nil {
		return err
	}
	settings := map[string]any{"clients": []panelClient{client}}
	bs, _ := json.Marshal(settings)
	f := url.Values{}
	f.Set("id", strconv.Itoa(inboundID))
	f.Set("settings", string(bs))
	msg, err := a.panelDoJSON(cli, http.MethodPost, "/panel/api/inbounds/addClient", f)
	if err != nil {
		return err
	}
	if !msg.Success {
		return errors.New(msg.Msg)
	}
	return nil
}

func (a *App) panelListInbounds(cli *http.Client) ([]panelInbound, error) {
	msg, err := a.panelDoJSON(cli, http.MethodGet, "/panel/api/inbounds/list", nil)
	if err != nil {
		return nil, err
	}
	if !msg.Success {
		return nil, errors.New(msg.Msg)
	}
	rows := make([]panelInbound, 0)
	if err := json.Unmarshal(msg.Obj, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (a *App) findClientByEmail(inbounds []panelInbound, email string) (panelInbound, panelClient, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, ib := range inbounds {
		var raw struct {
			Clients []panelClient `json:"clients"`
		}
		if err := json.Unmarshal([]byte(ib.Settings), &raw); err != nil {
			continue
		}
		for _, c := range raw.Clients {
			if strings.ToLower(c.Email) == email {
				cid := c.ID
				switch ib.Protocol {
				case "trojan":
					cid = c.Password
				case "shadowsocks":
					cid = c.Email
				}
				return ib, c, cid, nil
			}
		}
	}
	return panelInbound{}, panelClient{}, "", errors.New("client not found")
}

func (a *App) panelSetClientEnable(username, password, email string, enable bool) error {
	cli, err := a.panelClient(username, password)
	if err != nil {
		return err
	}
	inbounds, err := a.panelListInbounds(cli)
	if err != nil {
		return err
	}
	ib, c, cid, err := a.findClientByEmail(inbounds, email)
	if err != nil {
		return err
	}
	c.Enable = enable
	settings := map[string]any{"clients": []panelClient{c}}
	bs, _ := json.Marshal(settings)
	f := url.Values{}
	f.Set("id", strconv.Itoa(ib.ID))
	f.Set("settings", string(bs))
	msg, err := a.panelDoJSON(cli, http.MethodPost, "/panel/api/inbounds/updateClient/"+url.PathEscape(cid), f)
	if err != nil {
		return err
	}
	if !msg.Success {
		return errors.New(msg.Msg)
	}
	return nil
}

func (a *App) panelDeleteClient(username, password string, inboundID int, email string) error {
	cli, err := a.panelClient(username, password)
	if err != nil {
		return err
	}
	msg, err := a.panelDoJSON(cli, http.MethodPost, fmt.Sprintf("/panel/api/inbounds/%d/delClientByEmail/%s", inboundID, url.PathEscape(email)), url.Values{})
	if err != nil {
		return err
	}
	if msg.Success {
		return nil
	}
	// Fallback: some protocols/emails are not matched by delClientByEmail.
	inbounds, err := a.panelListInbounds(cli)
	if err != nil {
		return errors.New(msg.Msg)
	}
	ib, _, cid, err := a.findClientByEmail(inbounds, email)
	if err != nil {
		return errors.New(msg.Msg)
	}
	msg2, err := a.panelDoJSON(cli, http.MethodPost, fmt.Sprintf("/panel/api/inbounds/%d/delClient/%s", ib.ID, url.PathEscape(cid)), url.Values{})
	if err != nil {
		return err
	}
	if !msg2.Success {
		return errors.New(msg2.Msg)
	}
	return nil
}

func (a *App) panelOnlineSet(username, password string) (map[string]bool, error) {
	cli, err := a.panelClient(username, password)
	if err != nil {
		return nil, err
	}
	msg, err := a.panelDoJSON(cli, http.MethodPost, "/panel/api/inbounds/onlines", url.Values{})
	if err != nil {
		return nil, err
	}
	if !msg.Success {
		if msg.Msg == "" {
			msg.Msg = "panel onlines failed"
		}
		return nil, errors.New(msg.Msg)
	}
	list := make([]string, 0)
	if len(msg.Obj) > 0 {
		if err := json.Unmarshal(msg.Obj, &list); err != nil {
			return nil, err
		}
	}
	out := make(map[string]bool, len(list))
	for _, email := range list {
		out[strings.ToLower(strings.TrimSpace(email))] = true
	}
	return out, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
	_ = bytes.MinRead
}
