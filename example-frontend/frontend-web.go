package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var slog *zap.SugaredLogger
var logger *zap.Logger

var (
	keycloakOauthConfig *oauth2.Config
	// TODO: randomize it
	oauthStateString = "pseudo-random"

	// Session store의 키 값
	// TODO: randomize it
	key = []byte("super-secret-key")
)

func init() {

	// Logging configuration

	// rawJSON := []byte(`{
	//     "level": "debug",
	//     "encoding": "json",
	//     "outputPaths": ["stdout"],
	//     "encoderConfig": {
	//         "levelKey": "level",
	//         "messageKey": "message",
	//         "levelEncoder": "lowercase"
	//     }
	// }`)
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stdout"}
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)

	var err error
	logger, err = config.Build()
	if err != nil {
		log.Fatal(err)
	}

	defer logger.Sync() // flushes buffer, if any
	slog = logger.Sugar()

	// Viper configuration
	initViper()

	// Keycloak OAuth2 configuration
	keycloakOauthConfig = &oauth2.Config{
		ClientID:     viper.GetString("keycloak.clientID"),
		ClientSecret: viper.GetString("keycloak.clientSecret"),
		RedirectURL:  viper.GetString("keycloak.redirectURL"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  viper.GetString("keycloak.authURL"),
			TokenURL: viper.GetString("keycloak.tokenURL"),
		},
	}

}

// initViper initializes viper configuration.
func initViper() {
	viper.SetConfigName("config-keycloak") // name of config file (without extension)
	viper.SetConfigType("json")            // REQUIRED if the config file does not have the extension in the name
	// viper.AddConfigPath("/etc/appname/")   // path to look for the config file in
	// viper.AddConfigPath("$HOME/.appname")  // call multiple times to add many search paths
	viper.AddConfigPath(".") // optionally look for config in the working directory
	viper.SetEnvPrefix("demo")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("unable to initialize viper: %w", err))
	}
	slog.Debugf("viper config initialized")
}

// TemplateRenderer is a custom html/template renderer for Echo framework.
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document.
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

// Exists returns whether the given file or directory exists or not.
func Exists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// parseKeycloakRSAPublicKey parses the RSA public key from the base64 string.
func parseKeycloakRSAPublicKey(base64Str string) (*rsa.PublicKey, error) {
	buf, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if ok {
		return publicKey, nil
	}
	return nil, fmt.Errorf("unexpected key type %T", publicKey)
}

// getKey returns the public key for verifying the JWT token.
func getKey(token *jwt.Token) (interface{}, error) {

	base64Str := viper.GetString("keycloak.realmRS256PublicKey")
	publicKey, _ := parseKeycloakRSAPublicKey(base64Str)

	key, _ := jwk.New(publicKey)

	var pubkey interface{}
	if err := key.Raw(&pubkey); err != nil {
		return nil, fmt.Errorf("unable to get the public key. error: %s", err.Error())
	}

	return pubkey, nil
}

// Middlewares is the struct for middlewares.
type Middlewares struct {
}

func (m *Middlewares) checkSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := session.Get("session", c)
		slog.Debugf("sess.Values[authenticated]: %v", sess.Values["authenticated"])
		slog.Debugf("sess.Values[name]: %v", sess.Values["name"])
		if sess.Values["authenticated"] != true {
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return next(c)
	}
}

// Handlers is the struct for handlers.
type Handlers struct {
}

func (h *Handlers) index(c echo.Context) error {
	return c.Render(http.StatusOK, "index.html", nil)
}

func (h *Handlers) main(c echo.Context) error {
	return c.Render(http.StatusOK, "main.html", nil)
}

func (h *Handlers) loginKeycloak(c echo.Context) error {

	url := keycloakOauthConfig.AuthCodeURL(oauthStateString)
	return c.Redirect(http.StatusMovedPermanently, url)
}

func (h *Handlers) authCallback(c echo.Context) error {

	slog.Debug(c.Request().Header)
	slog.Debug(c.Request().FormValue("code"))

	code := c.Request().FormValue("code")

	token, err := keycloakOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	slog.Debugf("token: %v", token)
	slog.Debugf("token.AccessToken: %v", token.AccessToken)

	// Parse JWT token
	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(token.AccessToken, claims, getKey)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	// Get claims
	claims, ok := jwtToken.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
	if !ok {
		c.String(http.StatusUnauthorized, "failed to cast claims as jwt.MapClaims")
	}

	// Set session
	sess, _ := session.Get("session", c)

	// Options stores configuration for a session or session store.
	// Fields are a subset of http.Cookie fields.
	// https://pkg.go.dev/github.com/gorilla/sessions@v1.2.1#Options
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}
	// Set user as authenticated
	sess.Values["authenticated"] = true
	// Set user name
	sess.Values["name"] = claims["name"]
	// Set more values here
	// ...
	sess.Save(c.Request(), c.Response())

	return c.Render(http.StatusOK, "main.html", nil)
}

func main() {

	var enabled = viper.GetBool("keycloak.enabled")
	slog.Debugf("enabled: %v", enabled)

	// Set web assets path to the current directory (usually for the production)
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exePath := filepath.Dir(ex)
	slog.Debugf("exePath: ", exePath)
	webPath := filepath.Join(exePath, "web")

	indexPath := filepath.Join(webPath, "public", "index.html")
	slog.Debugf("indexPath: ", indexPath)
	if !Exists(indexPath) {
		// Set web assets path to the project directory (usually for the development)
		path, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
		if err != nil {
			panic(err)
		}
		projectPath := strings.TrimSpace(string(path))
		webPath = filepath.Join(projectPath, "web")
	}
	slog.Debugf("webPath: ", webPath)
	slog.Debug("Start - Echo framework")
	e := echo.New()

	// e.Static("/", webPath+"/assets")
	// e.Static("/js", webPath+"/assets/js")
	// e.Static("/css", webPath+"/assets/css")
	// e.Static("/introspect", webPath+"/assets/introspect")

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(webPath + "/public/*.html")),
	}
	e.Renderer = renderer

	middlewares := &Middlewares{}
	handlers := &Handlers{}

	// Middleware for session management
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(key))))

	e.GET("/", handlers.index)
	e.GET("/auth", handlers.loginKeycloak)
	e.GET("/auth/callback", handlers.authCallback)

	g := e.Group("/main")
	g.Use(middlewares.checkSession)
	g.GET("", handlers.main)

	e.Logger.Fatal(e.Start(":3000"))
}
