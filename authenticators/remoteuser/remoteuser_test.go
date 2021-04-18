package remoteuser

import (
	"crypto/rsa"
	"io/ioutil"
	"testing"

	"github.com/choria-io/aaasvc/api/gen/models"
	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestWithGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authenticators/Remoteuser")
}

var _ = Describe("Authenticators/Remoteuser", func() {
	var (
		conf *AuthenticatorConfig
		req  *models.LoginRequest
		auth *Authenticator
		err  error
		log  *logrus.Entry
	)

	BeforeEach(func() {
		conf = &AuthenticatorConfig{
			SigningKey:    "../userlist/testdata/key.pem",
			TokenValidity: "1h",
			DefaultUser: DefaultUser{
				ACLs:          []string{"puppet.*"},
				OPAPolicyFile: "../userlist/testdata/test.rego",
				Properties:    map[string]string{"group": "admins"},
			},
		}

		logger := logrus.New()
		logger.Out = ioutil.Discard
		log = logrus.NewEntry(logger)
		req = &models.LoginRequest{}
		auth, err = New(conf, log, "ginkgo")
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("New", func() {
		It("Should parse the duration", func() {
			_, err := New(&AuthenticatorConfig{
				TokenValidity: "1y",
			}, log, "ginkgo")
			Expect(err).To(MatchError("invalid token validity: time: unknown unit \"y\" in duration \"1y\""))

			_, err = New(&AuthenticatorConfig{
				TokenValidity: "1h",
			}, log, "ginkgo")
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("Login", func() {
		It("Should handle non-existent X-Remote-User", func() {
			res := auth.Login(req, nil)
			Expect(res.Error).To(Equal("Login failed"))
		})

		It("Should handle empty X-Remote-User", func() {
			remoteuser := ""
			res := auth.Login(req, &remoteuser)
			Expect(res.Error).To(Equal("Login failed"))
		})

		It("Should ignore any user/passwd pair", func() {
			req.Username = "bob"
			req.Password = "fooo"
			res := auth.Login(req, nil)
			Expect(res.Error).To(Equal("Login failed"))
		})

		It("Should generate correct claims", func() {
			req.Username = "bob"
			req.Password = "doesnotmatter"
			remoteuser := "alice"
			res := auth.Login(req, &remoteuser)
			Expect(res.Error).To(Equal(""))

			pub, err := signKey()
			Expect(err).ToNot(HaveOccurred())

			token, err := jwt.Parse(res.Token, func(token *jwt.Token) (interface{}, error) {
				return pub, nil
			})
			Expect(err).ToNot(HaveOccurred())

			claims, ok := token.Claims.(jwt.MapClaims)
			Expect(ok).To(BeTrue())

			caller, ok := claims["callerid"].(string)
			Expect(ok).To(BeTrue())
			Expect(caller).To(Equal("up=alice"))

			agents, ok := claims["agents"].([]interface{})
			Expect(ok).To(BeTrue())
			Expect(agents).To(HaveLen(1))
			Expect(agents[0].(string)).To(Equal("puppet.*"))

			policy, ok := claims["opa_policy"].(string)
			Expect(ok).To(BeTrue())
			Expect(policy).To(Equal(readFixture("../userlist/testdata/test.rego")))

			props, ok := claims["user_properties"].(map[string]interface{})
			Expect(ok).To(BeTrue())
			group, ok := props["group"].(string)
			Expect(ok).To(BeTrue())
			Expect(group).To(Equal("admins"))
		})
	})
})

func readFixture(f string) string {
	c, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}

	return string(c)
}

func signKey() (*rsa.PublicKey, error) {
	certBytes, err := ioutil.ReadFile("../userlist/testdata/cert.pem")
	if err != nil {
		return nil, err
	}

	signKey, err := jwt.ParseRSAPublicKeyFromPEM(certBytes)
	if err != nil {
		return nil, err
	}

	return signKey, nil
}
