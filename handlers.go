package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"net/http"
)

type ApiHandler struct {
	doHandle func(w http.ResponseWriter, r *http.Request)
}

func (h *ApiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.doHandle(w, r)
}

type tokenClaims struct {
	Login  string `mapstructure:"login"`
	UserId int64  `mapstructure:"user_id"`
	Exp    int64  `mapstructure:"exp"`
}

type ApiHandlerWithAuth struct {
	ApiHandler
	conf     *config
	doHandle func(w http.ResponseWriter, r *http.Request, userId int64)
}

// TODO: close all bodies
func (h *ApiHandlerWithAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	h.doHandle(w, r, claims.UserId)
}

func replyWithError(w http.ResponseWriter, code int, err error) {
	res := struct {
		Error string `json:"error"`
	}{err.Error()}
	resBody, _ := json.Marshal(res)
	w.WriteHeader(code)
	if _, err := fmt.Fprint(w, string(resBody)); err != nil {
		logE.Printf("reply with error: %v", err)
	}
}
