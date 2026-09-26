// Package handler exposes the same routes and parameter styles as FinanSu's
// openapi.yaml for users / mail_auth / current_user, plus the new
// POST /mail_auth/firebase_signin.
package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/hikahana/auth-poc-test/examples/finansu-mock/usecase"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	mailAuth *usecase.MailAuthUseCase
	user     *usecase.UserUseCase
	firebase *usecase.FirebaseAuthUseCase
}

func New(m *usecase.MailAuthUseCase, u *usecase.UserUseCase, f *usecase.FirebaseAuthUseCase) *Handler {
	return &Handler{mailAuth: m, user: u, firebase: f}
}

func (h *Handler) Register(e *echo.Echo) {
	e.POST("/users", h.PostUser)
	e.POST("/mail_auth/signup", h.PostMailAuthSignup)
	e.POST("/mail_auth/signin", h.PostMailAuthSignin)
	e.DELETE("/mail_auth/signout", h.DeleteMailAuthSignout)
	e.GET("/mail_auth/is_signin", h.GetMailAuthIsSignin)
	e.GET("/current_user", h.GetCurrentUser)

	e.POST("/mail_auth/firebase_signin", h.PostMailAuthFirebaseSignin)
	e.POST("/mail_auth/firebase_signup", h.PostMailAuthFirebaseSignup)
}

func (h *Handler) PostUser(c echo.Context) error {
	bureauID, err1 := strconv.Atoi(c.QueryParam("bureau_id"))
	roleID, err2 := strconv.Atoi(c.QueryParam("role_id"))
	if c.QueryParam("name") == "" || err1 != nil || err2 != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "name, bureau_id, role_id are required")
	}
	user, err := h.user.Create(c.Request().Context(), c.QueryParam("name"), bureauID, roleID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, user)
}

func (h *Handler) PostMailAuthSignup(c echo.Context) error {
	userID, err := strconv.Atoi(c.QueryParam("user_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "user_id is required")
	}
	token, err := h.mailAuth.SignUp(c.Request().Context(), c.QueryParam("email"), c.QueryParam("password"), userID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, token)
}

func (h *Handler) PostMailAuthSignin(c echo.Context) error {
	token, err := h.mailAuth.SignIn(c.Request().Context(), c.QueryParam("email"), c.QueryParam("password"))
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}
	return c.JSON(http.StatusOK, token)
}

func (h *Handler) DeleteMailAuthSignout(c echo.Context) error {
	if err := h.mailAuth.SignOut(c.Request().Context(), c.Request().Header.Get("Access-Token")); err != nil {
		return err
	}
	return c.String(http.StatusOK, "Success Sign Out")
}

func (h *Handler) GetMailAuthIsSignin(c echo.Context) error {
	return c.JSON(http.StatusOK, h.mailAuth.IsSignIn(c.Request().Context(), c.Request().Header.Get("Access-Token")))
}

func (h *Handler) GetCurrentUser(c echo.Context) error {
	user, err := h.user.GetCurrentUser(c.Request().Context(), c.Request().Header.Get("Access-Token"))
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid access token")
	}
	return c.JSON(http.StatusOK, user)
}

type firebaseSigninRequest struct {
	IDToken string `json:"id_token"`
}

// PostMailAuthFirebaseSignin takes the ID token in a JSON body rather than a
// query parameter like the other mail_auth routes: it is a bearer credential
// and must not end up in access logs.
func (h *Handler) PostMailAuthFirebaseSignin(c echo.Context) error {
	var req firebaseSigninRequest
	if err := c.Bind(&req); err != nil || req.IDToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id_token is required")
	}

	token, err := h.firebase.SignIn(c.Request().Context(), req.IDToken)
	if err != nil {
		return firebaseError(c, err)
	}
	return c.JSON(http.StatusOK, token)
}

type firebaseSignupRequest struct {
	IDToken  string `json:"id_token"`
	Name     string `json:"name"`
	BureauID int    `json:"bureau_id"`
}

// PostMailAuthFirebaseSignup takes no email: it is read from the ID token.
func (h *Handler) PostMailAuthFirebaseSignup(c echo.Context) error {
	var req firebaseSignupRequest
	if err := c.Bind(&req); err != nil || req.IDToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id_token is required")
	}

	token, err := h.firebase.SignUp(c.Request().Context(), req.IDToken, req.Name, req.BureauID)
	if err != nil {
		return firebaseError(c, err)
	}
	return c.JSON(http.StatusCreated, token)
}

// firebaseError maps the Firebase use case errors. A whitelisted member
// without an account gets 404 with registrationRequired, so the frontend can
// open the sign-up form with the email fixed.
func firebaseError(c echo.Context, err error) error {
	var regErr *usecase.RegistrationRequiredError
	switch {
	case errors.As(err, &regErr):
		return c.JSON(http.StatusNotFound, map[string]any{
			"message": err.Error(), "registrationRequired": true, "email": regErr.Email,
		})
	case errors.Is(err, usecase.ErrInvalidToken):
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	case errors.Is(err, usecase.ErrInvalidSignUp):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, usecase.ErrNotAllowed),
		errors.Is(err, usecase.ErrEmailNotVerified),
		errors.Is(err, usecase.ErrNoAccount):
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	case errors.Is(err, usecase.ErrAlreadyLinked), errors.Is(err, usecase.ErrAlreadyRegistered):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	default:
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadGateway, "auth platform unavailable")
	}
}
