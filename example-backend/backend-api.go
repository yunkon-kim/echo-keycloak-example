package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var slog *zap.SugaredLogger
var logger *zap.Logger

func init() {

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

// parseKeycloakRSAPublicKey parses a base64 encoded public key into an rsa.PublicKey.
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

// getKey is the KeyFunc for the JWT middleware.
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

// retrospectToken is the SuccessHandler for the JWT middleware.
// It will be called if jwt.Parse succeeds and set the claims in the context.
// (Briefly, it is the process of checking whether a (previously) issued token is still valid or not.)
func retrospectToken(c echo.Context) {
	slog.Debug("Start - retrospectToken, which is the SuccessHandler")

	var baseUrl = viper.GetString("keycloak.baseUrl")
	var clientID = viper.GetString("keycloak.clientId")
	var clientSecret = viper.GetString("keycloak.clientSecret")
	var realm = viper.GetString("keycloak.realm")

	token, ok := c.Get("user").(*jwt.Token) // by default token is stored under `user` key
	if !ok {
		c.String(http.StatusUnauthorized, "JWT token missing or invalid")
	}
	claims, ok := token.Claims.(jwt.MapClaims) // by default claims is of type `jwt.MapClaims`
	if !ok {
		c.String(http.StatusUnauthorized, "failed to cast claims as jwt.MapClaims")
	}

	// slog.Debugf("token:", token)
	slog.Debugf("token.Raw:", token.Raw)
	slog.Debugf("claims:", claims)

	var ctx = c.Request().Context()
	// c.Set(fmt.Sprint(enums.ContextKeyClaims), claims)

	client := gocloak.NewClient(baseUrl)

	rptResult, err := client.RetrospectToken(ctx, token.Raw, clientID, clientSecret, realm)
	if err != nil {
		c.String(http.StatusUnauthorized, "Inspection failed:"+err.Error())
	}

	slog.Debugf("rptResult:", rptResult)

	if !*rptResult.Active {
		c.String(http.StatusUnauthorized, "Token is not active")
	}

	slog.Debug("End - retrospectToken, which is the SuccessHandler")
}

type Handlers struct {
}

// accessible is the handler for the unauthenticated group.
func (h *Handlers) accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

// restricted is the handler for the restricted group.
func (h *Handlers) restricted(c echo.Context) error {
	slog.Debug("restricted start")
	token := c.Get("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	// slog.Debugf("Claims from JWT Token Print claims in-detail, format 'key: value'")

	name := claims["name"].(string)

	slog.Debug("restricted end")
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func main() {

	initViper()
	var enabled = viper.GetBool("keycloak.enabled")
	slog.Debugf("enabled: %v", enabled)

	e := echo.New()

	handlers := &Handlers{}

	e.Use(middleware.Logger())

	// Unauthenticated route
	e.GET("/", handlers.accessible)

	// Configure middleware with the custom claims type
	config := echojwt.Config{
		KeyFunc:        getKey,
		SuccessHandler: retrospectToken,
	}

	// Restricted group
	r := e.Group("/restricted")
	r.Use(echojwt.WithConfig(config))

	r.GET("", handlers.restricted)

	e.Logger.Fatal(e.Start(":1323"))

}
