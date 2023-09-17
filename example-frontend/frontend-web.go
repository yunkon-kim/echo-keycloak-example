package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/labstack/echo/v4"
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

// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func Exists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type Handlers struct {
}

func (h *Handlers) index(c echo.Context) error {
	return c.Render(http.StatusOK, "index.html", nil)
}

func (h *Handlers) loginKeycloak(c echo.Context) error {

	url := keycloakOauthConfig.AuthCodeURL(oauthStateString)
	//	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	//
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

	handlers := &Handlers{}

	e.GET("/", handlers.index)
	e.GET("/auth", handlers.loginKeycloak)
	e.GET("/auth/callback", handlers.authCallback)

	e.Logger.Fatal(e.Start(":3000"))
}

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
