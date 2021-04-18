// Package remoteuser provides an authentication system with login delegation
//
// The user's identity validation is delegated to a front-end. This authenticator
// simply consumes the value of the X-Remote-User HTTP header and generates a signed
// authentication token with the same ACLs for all users.
//
// In the future, per-user ACLs/roles/etc could even be part of other
// headers. Alternatively, there could also be a local DB here (as in
// the userlist authenticator). Or a even a combination of both!
package remoteuser

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/authenticators"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// AuthenticatorConfig configures the remoteuser authenticator
type AuthenticatorConfig struct {
	DefaultUser   DefaultUser `json:"default_user"`
	TokenValidity string      `json:"validity"`
	SigningKey    string      `json:"signing_key"`
}

// Authenticator is an authenticator blindly trusting X-Remote-User and using a default config for all users
type Authenticator struct {
	c             *AuthenticatorConfig
	validity      time.Duration
	log           *logrus.Entry
	site          string
	userFileMtime time.Time
	sync.Mutex
}

// New creates an instance of the authenticator
func New(c *AuthenticatorConfig, log *logrus.Entry, site string) (a *Authenticator, err error) {
	validity, err := time.ParseDuration(c.TokenValidity)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token validity")
	}

	a = &Authenticator{
		c:        c,
		validity: validity,
		log:      log.WithField("authenticator", "remoteuser"),
		site:     site,
	}

	return a, nil
}

// Login logs a pre-authenticated user filling the token with a default user template
func (a *Authenticator) Login(req *models.LoginRequest, ru *string) (resp *models.LoginResponse) {
	timer := authenticators.ProcessTime.WithLabelValues(a.site, "remoteuser")
	obs := prometheus.NewTimer(timer)
	defer obs.ObserveDuration()

	resp = a.processLogin(ru)
	if resp.Error != "" {
		authenticators.ErrCtr.WithLabelValues(a.site, "remoteuser").Inc()
	}

	return resp
}

func (a *Authenticator) processLogin(ru *string) (resp *models.LoginResponse) {
	resp = &models.LoginResponse{}

	if ru == nil || len(*ru) == 0 {
		a.log.Warnf("Login failed as there was no X-Remote-User present in the request")
		resp.Error = "Login failed"
		return
	}

	remoteuser := *ru

	claims := map[string]interface{}{
		"exp":      time.Now().UTC().Add(a.validity).Unix(),
		"nbf":      time.Now().UTC().Add(-1 * time.Minute).Unix(),
		"iat":      time.Now().UTC().Unix(),
		"iss":      "Choria Remoteuser Authenticator",
		"callerid": fmt.Sprintf("up=%s", remoteuser),
		"sub":      "choria_client",
		"agents":   a.c.DefaultUser.ACLs,
		"ou":       "choria",
	}

	if a.c.DefaultUser.Organization != "" {
		claims["ou"] = a.c.DefaultUser.Organization
	}

	policy, err := a.c.DefaultUser.OpenPolicy()
	if err != nil {
		a.log.Warnf("Reading OPA policy for user %s failed: %s", remoteuser, err)
		resp.Error = "Login failed"
		return
	}

	if len(a.c.DefaultUser.Properties) > 0 {
		claims["user_properties"] = a.c.DefaultUser.Properties
	}

	if policy != "" {
		claims["opa_policy"] = policy
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), jwt.MapClaims(claims))

	signKey, err := a.signKey()
	if err != nil {
		a.log.Errorf("Could not load signing key during login request for user %s: %s: %s", remoteuser, a.c.SigningKey, err)
		resp.Error = "Could not load signing key from disk"
		return
	}

	signed, err := token.SignedString(signKey)
	if err != nil {
		a.log.Errorf("Could not sign JWT for %s: %s", remoteuser, err)
		resp.Error = "Could not sign JWT token"
		return
	}

	resp.Token = signed

	a.log.Infof("Logged in user %s", remoteuser)

	return resp

}

func (a *Authenticator) signKey() (*rsa.PrivateKey, error) {
	pkeyBytes, err := ioutil.ReadFile(a.c.SigningKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not read")
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(pkeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse")
	}

	return signKey, nil
}
