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
	"github.com/gookit/goutil"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"
	"github.com/yunkon-kim/echo-keycloak-example/pkg/enums"
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

// accessible is the handler for the unauthenticated group.
func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

// restricted is the handler for the restricted group.
func restricted(c echo.Context) error {
	slog.Debug("restricted start")
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)

	slog.Debugf("Claims from JWT Token Print claims in-detail, format 'key: value'")

	name := claims["name"].(string)

	slog.Debug("restricted end")
	return c.String(http.StatusOK, "Welcome "+name+"!")
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

	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)

	var ctx = c.Request().Context()
	c.Set(fmt.Sprint(enums.ContextKeyClaims), claims)

	client := gocloak.NewClient(baseUrl)
	token, err := client.LoginClient(ctx, clientID, clientSecret, realm)
	if err != nil {
		c.String(http.StatusUnauthorized, "Keycloak login failed:"+err.Error())
	}

	rptResult, err := client.RetrospectToken(ctx, token.AccessToken, clientID, clientSecret, realm)
	if err != nil {
		c.String(http.StatusUnauthorized, "Inspection failed:"+err.Error())
	}

	if !*rptResult.Active {
		c.String(http.StatusUnauthorized, "Token is not active")
	}

	slog.Debug("End - retrospectToken, which is the SuccessHandler")
}

func main() {

	initViper()
	var enabled = viper.GetBool("keycloak.enabled")
	slog.Debugf("enabled: %v", enabled)

	e := echo.New()

	e.Use(middleware.Logger())

	// Unauthenticated route
	e.GET("/", accessible)

	// Configure middleware with the custom claims type
	config := echojwt.Config{
		KeyFunc:        getKey,
		SuccessHandler: retrospectToken,
	}

	// Restricted group
	r := e.Group("/restricted")
	r.Use(echojwt.WithConfig(config))

	r.GET("", restricted)

	e.Logger.Fatal(e.Start(":1323"))

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

type JwtHelper struct {
	claims       jwt.MapClaims
	realmRoles   []string
	accountRoles []string
	scopes       []string
}

func NewJwtHelper(claims jwt.MapClaims) *JwtHelper {

	return &JwtHelper{
		claims:       claims,
		realmRoles:   parseRealmRoles(claims),
		accountRoles: parseAccountRoles(claims),
		scopes:       parseScopes(claims),
	}
}

func (j *JwtHelper) GetUserId() (string, error) {
	return j.claims.GetSubject()
}

func (j *JwtHelper) IsUserInRealmRole(role string) bool {
	return goutil.Contains(j.realmRoles, role)
}

func (j *JwtHelper) TokenHasScope(scope string) bool {
	return goutil.Contains(j.scopes, scope)
}

func parseRealmRoles(claims jwt.MapClaims) []string {
	var realmRoles []string = make([]string, 0)

	if claim, ok := claims["realm_access"]; ok {
		if roles, ok := claim.(map[string]interface{})["roles"]; ok {
			for _, role := range roles.([]interface{}) {
				realmRoles = append(realmRoles, role.(string))
			}
		}
	}
	return realmRoles
}

func parseAccountRoles(claims jwt.MapClaims) []string {
	var accountRoles []string = make([]string, 0)

	if claim, ok := claims["resource_access"]; ok {
		if acc, ok := claim.(map[string]interface{})["account"]; ok {
			if roles, ok := acc.(map[string]interface{})["roles"]; ok {
				for _, role := range roles.([]interface{}) {
					accountRoles = append(accountRoles, role.(string))
				}
			}
		}
	}
	return accountRoles
}

func parseScopes(claims jwt.MapClaims) []string {
	scopeStr, err := parseString(claims, "scope")
	if err != nil {
		return make([]string, 0)
	}
	scopes := strings.Split(scopeStr, " ")
	return scopes
}

func parseString(claims jwt.MapClaims, key string) (string, error) {
	var (
		ok  bool
		raw interface{}
		iss string
	)
	raw, ok = claims[key]
	if !ok {
		return "", nil
	}

	iss, ok = raw.(string)
	if !ok {
		return "", fmt.Errorf("key %s is invalid", key)
	}
	return iss, nil
}
