package main

import (
	"database/sql"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"net/http"
)

type tokenClaims struct {
	Login  string `mapstructure:"login"`
	UserId int64  `mapstructure:"user_id"`
	Exp    int64  `mapstructure:"exp"`
}

type authHandler struct {
	handler
	next func(w http.ResponseWriter, r *http.Request, userId int64, db *sql.DB, conf *config)
}

func newAuthHandler(next func(w http.ResponseWriter, r *http.Request, userId int64, db *sql.DB, conf *config), db *sql.DB, conf *config) *authHandler {
	return &authHandler{next: next, handler: handler{db: db, conf: conf}}
}

// TODO: close all bodies
func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	cookie, err := r.Cookie("access_token")
	if err != nil {
		err = fmt.Errorf("extract auth cookie: %v", err)
		replyWithError(w, http.StatusForbidden, err)
		return
	}
	token, err := jwt.Parse(cookie.Value, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signature method")
		}
		return []byte(h.conf.JwtSignKey), nil
	})
	if err != nil {
		replyWithError(w, http.StatusForbidden, fmt.Errorf("parse jwt token: %v", err))
		return
	}
	claimsMap, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		err = fmt.Errorf("invalid token")
		replyWithError(w, http.StatusForbidden, err)
		return
	}
	claims := &tokenClaims{}
	if err := mapstructure.Decode(claimsMap, claims); err != nil {
		err = fmt.Errorf("decode auth token: %v", err)
		logE.Print(err)
		replyWithError(w, http.StatusForbidden, err)
		return
	}
	h.next(w, r, claims.UserId, h.db, h.conf)
}
