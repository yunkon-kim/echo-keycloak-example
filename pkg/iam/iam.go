package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type identityAccessManager struct {
	baseUrl      string
	realm        string
	clientId     string
	clientSecret string
}

func NewIdentityManager() *identityAccessManager {
	return &identityAccessManager{
		baseUrl:      viper.GetString("keycloak.baseUrl"),
		realm:        viper.GetString("keycloak.realm"),
		clientId:     viper.GetString("keycloak.clientId"),
		clientSecret: viper.GetString("keycloak.clientSecret"),
	}
}

func (iam *identityAccessManager) loginClient(ctx context.Context) (*gocloak.JWT, error) {
	client := gocloak.NewClient(iam.baseUrl)

	token, err := client.LoginClient(ctx, iam.clientId, iam.clientSecret, iam.realm)
	if err != nil {
		return nil, errors.Wrap(err, "unable to login the rest client")
	}
	return token, nil
}

func (iam *identityAccessManager) CreateUser(ctx context.Context, user gocloak.User, password string, role string) (*gocloak.User, error) {

	token, err := iam.loginClient(ctx)
	if err != nil {
		return nil, err
	}

	client := gocloak.NewClient(iam.baseUrl)

	userId, err := client.CreateUser(ctx, token.AccessToken, iam.realm, user)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create the user")
	}

	err = client.SetPassword(ctx, token.AccessToken, userId, iam.realm, password, false)
	if err != nil {
		return nil, errors.Wrap(err, "unable to set the password for the user")
	}

	var roleNameLowerCase = strings.ToLower(role)
	roleKeycloak, err := client.GetRealmRole(ctx, token.AccessToken, iam.realm, roleNameLowerCase)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("unable to get role by name: '%v'", roleNameLowerCase))
	}
	err = client.AddRealmRoleToUser(ctx, token.AccessToken, iam.realm, userId, []gocloak.Role{
		*roleKeycloak,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to add a realm role to user")
	}

	userKeycloak, err := client.GetUserByID(ctx, token.AccessToken, iam.realm, userId)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get recently created user")
	}

	return userKeycloak, nil
}

func (iam *identityAccessManager) RetrospectToken(ctx context.Context, accessToken string) (*gocloak.IntroSpectTokenResult, error) {

	client := gocloak.NewClient(iam.baseUrl)

	rptResult, err := client.RetrospectToken(ctx, accessToken, iam.clientId, iam.clientSecret, iam.realm)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrospect token")
	}
	return rptResult, nil
}
