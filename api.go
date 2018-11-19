package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"log"
	"net/http"
	"strconv"
	"time"
)

type Api struct {
	db *sql.DB
	conf *config
}

func NewApi(db *sql.DB, conf *config) *Api {
	return &Api{db, conf}
}

// TODO: wrapper for logging requests and responses (maybe x-req-id?)
func (a *Api) Handler(f func(w http.ResponseWriter, r *http.Request)) *ApiHandler {
	return &ApiHandler{f}
}

func (a *Api) HandlerWithAuth(f func(w http.ResponseWriter, r *http.Request, userId int64)) *ApiHandlerWithAuth {
	return &ApiHandlerWithAuth{conf: a.conf, doHandle: f}
}

// Register new user by putting corresponding row into 'users' table
func (a *Api) HandleRegistration(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		replyWithError(w, http.StatusBadRequest, fmt.Errorf("decode request body: %v", err))
		return
	}
	if err := insertUser(a.db, reqBody.Login, reqBody.Password, reqBody.Name); err != nil {
		err = fmt.Errorf("insert new user: %v", err)
		logE.Print(err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
}

// Authorize user if exists and provide her with access token
// TODO: implement refresh token procedure
func (a *Api) HandleAuthorization(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		err = fmt.Errorf("decode request body: %v", err)
		logI.Print(err)
		replyWithError(w, http.StatusBadRequest, err)
		return
	}
	rows, err := a.db.Query("SELECT id FROM users WHERE login=$1 AND password=$2", reqBody.Login, reqBody.Password)
	if err != nil {
		err = fmt.Errorf("select user with login %q: %v", reqBody.Login, err)
		logE.Print(err)
		replyWithError(w, http.StatusForbidden, err)
		return
	}
	if !rows.Next() {
		err = fmt.Errorf("no user with login %q: %v", reqBody.Login, err)
		logE.Print(err)
		replyWithError(w, http.StatusForbidden, err)
		return
	}
	var userId int64
	if err := rows.Scan(&userId); err != nil {
		err = fmt.Errorf("retrieve user id from db: %v", err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	claimsMap := make(map[string]interface{})
	if err := mapstructure.Decode(&tokenClaims{
		Login:  reqBody.Login,
		UserId: userId,
		Exp:    time.Now().Add(24 * time.Hour).Unix(),
	}, &claimsMap); err != nil {
		err = fmt.Errorf("encode token claims: %v", err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), jwt.MapClaims(claimsMap))
	tokenString, err := token.SignedString([]byte(a.conf.JwtSignKey))
	if err != nil {
		err = fmt.Errorf("error signing token for user %d: %v", userId, err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	resBody, err := json.Marshal(
		&struct {
			AccessToken string `json:"access_token"`
		}{
			AccessToken: tokenString,
		},
	)
	if err != nil {
		err = fmt.Errorf("marshall access token for user with id %d: %v", userId, err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	fmt.Fprint(w, string(resBody))
}

// Add new record
// Note: needs auth
func (a *Api) HandleNewRecord(w http.ResponseWriter, r *http.Request, userId int64) {
	var reqBody struct {
		Name     string `json:"name"`
		Duration int64  `json:"duration"`
		Content  string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		err = fmt.Errorf("decode request body: %v", err)
		logI.Print(err)
		replyWithError(w, http.StatusBadRequest, err)
		return
	}
	if err := insertRecord(a.db, reqBody.Name, reqBody.Content, userId); err != nil {
		err = fmt.Errorf("insert new record: %v", err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Share record to another user by creating new row in 'shared' table
// Note: needs auth
func (a *Api) HandleShareRecord(w http.ResponseWriter, r *http.Request, userId int64) {
	var reqBody struct {
		RecordId     int64 `json:"record_id"`
		UserId int64  `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		err = fmt.Errorf("decode share request body: %v", err)
		logI.Print(err)
		replyWithError(w, http.StatusBadRequest, err)
		return
	}
	qres, err := a.db.Exec(`
INSERT INTO shared(record_id, "to")
SELECT R.id, $1 FROM records R
WHERE owner_id=$2 AND R.id=$3;
`, reqBody.UserId, userId, reqBody.RecordId)
	if err != nil {
		err = fmt.Errorf("insert new shared record: %v", err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	if nrows, err := qres.RowsAffected(); err != nil || nrows == 0 {
		err = fmt.Errorf("while insert shared record: %d rows affected, error: %v", nrows, err)
		replyWithError(w, http.StatusNotAcceptable, err)
	}
}

// Unshare user's record by removing corresponding row in 'records' table
func (a *Api) HandleUnshareRecord(w http.ResponseWriter, r *http.Request, userId int64) {
	var reqBody struct {
		RecordId     int64 `json:"record_id"`
		UserId int64  `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		err = fmt.Errorf("decode share request body: %v", err)
		logI.Print(err)
		replyWithError(w, http.StatusBadRequest, err)
		return
	}
	qres, err := a.db.Exec(`
DELETE FROM shared S USING records R
WHERE R.id=$1 AND R.owner_id=$2 AND S.record_id=$1 AND S."to"=$3
`, reqBody.RecordId, userId, reqBody.UserId)
	if err != nil {
		err = fmt.Errorf("delete shared record: %v", err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	if nrows, err := qres.RowsAffected(); err != nil || nrows == 0 {
		err = fmt.Errorf("while delete shared record: %d rows affected, error: %v", nrows, err)
		replyWithError(w, http.StatusNotAcceptable, err)
	}
}

// List all records that are available to user by concatenating his own records and records shared to him by other users
// Note: needs auth
func (a *Api) HandleRecordsList(w http.ResponseWriter, r *http.Request, userId int64) {
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil {
		replyWithError(w, http.StatusBadRequest, fmt.Errorf("invalid offset param: %v", err))
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		replyWithError(w, http.StatusBadRequest, fmt.Errorf("invalid offset param: %v", err))
		return
	}
	const (
		sortByOwner = "owner"
		sortByRecord = "record"
	)
	sortby := r.URL.Query().Get("sort_by")
	if sortby != sortByOwner && sortby != sortByRecord {
		replyWithError(w, http.StatusBadRequest, fmt.Errorf("invalid sort_by param"))
		return
	}
	type shared struct {
		Id   int64  `json:"id"`
		Name string `json:"name"`
	}
	type record struct {
		Id        int64    `json:"id"`
		Name      string   `json:"name"`
		IsOwner   bool     `json:"is_owner"`
		OwnerId   int64    `json:"owner_id"`
		OwnerName string   `json:"owner_name"`
		SharedTo  []shared `json:"shared_to"`
	}
	resBody := struct {
		TotalCount int64    `json:"total_count"`
		Records    []record `json:"records"`
	}{}
	var orderSuffix string
	if sortby == sortByOwner {
		orderSuffix = "user_name"
	} else {
		orderSuffix = "rec_name"
	}
	log.Printf("order suffix: %s", orderSuffix)
	log.Printf("limit: %d", limit)
	log.Printf("offset: %d", offset)
	rows, err := a.db.Query(fmt.Sprintf(`
SELECT user_records.rec_id,
       user_records.rec_name,
       user_records.rec_owner,
       user_records.user_id,
       user_records.user_name,
       S."to",
       U.name
FROM (
        (SELECT R.id AS rec_id,
                R.name AS rec_name,
                R.owner_id=$1 AS rec_owner,
                U.id AS user_id,
                U.name AS user_name
         FROM ( (records R
                 JOIN users U ON R.owner_id=U.id)
               FULL OUTER JOIN SHARED S ON S.record_id=R.id)
         WHERE R.owner_id=$1
           OR S."to"=$1
         LIMIT $2
         OFFSET $3) AS user_records
      FULL OUTER JOIN SHARED S ON S.record_id=user_records.rec_id)
FULL OUTER JOIN users U ON S."to"=U.id
ORDER BY user_records.rec_owner DESC,
         %s,
         rec_id;
`, orderSuffix), userId, limit, offset)
	if err != nil {
		err = fmt.Errorf("select all records for user %d: %v", userId, err)
		logE.Print(err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	for rows.Next() {
		var rec record
		var sharedToId sql.NullInt64
		var sharedToName sql.NullString
		if err := rows.Scan(&rec.Id, &rec.Name, &rec.IsOwner, &rec.OwnerId, &rec.OwnerName, &sharedToId, &sharedToName); err != nil {
			err = fmt.Errorf("retrieve record from db for user %d: %v", rec.OwnerId, err)
			logE.Print(err)
			replyWithError(w, http.StatusInternalServerError, err)
			return
		}
		logI.Printf("record: %v", rec)
		if len(resBody.Records) > 0 && resBody.Records[len(resBody.Records)-1].Id == rec.Id {
			resBody.Records[len(resBody.Records)-1].SharedTo = append(resBody.Records[len(resBody.Records)-1].SharedTo,
				shared{sharedToId.Int64, sharedToName.String})
		} else {
			rec.SharedTo = []shared{}
			if sharedToId.Valid && sharedToName.Valid {
				rec.SharedTo = append(rec.SharedTo, shared{sharedToId.Int64, sharedToName.String})
			}
			resBody.Records = append(resBody.Records, rec)
		}
	}
	resBody.TotalCount = int64(len(resBody.Records))
	res, err := json.Marshal(resBody)
	if err != nil {
		err = fmt.Errorf("encode records list: %v", err)
		logE.Print(err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	fmt.Fprint(w, string(res))
}

// List all users who share their records
// Note: needs auth
func (a *Api) HandleSharersList(w http.ResponseWriter, r *http.Request, userId int64) {
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil {
		replyWithError(w, http.StatusBadRequest, fmt.Errorf("invalid offset param: %v", err))
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		replyWithError(w, http.StatusBadRequest, fmt.Errorf("invalid limit param: %v", err))
		return
	}
	rows, err := a.db.Query(`
SELECT DISTINCT R.owner_id,
                U.name,
                COUNT(DISTINCT R.id)
FROM ( SHARED S
       JOIN records R ON S.record_id=R.id
       JOIN users U ON R.owner_id=U.id)
GROUP BY R.owner_id,
         U.name
ORDER BY R.owner_id
LIMIT $1
OFFSET $2;
`, limit, offset)
	if err != nil {
		err = fmt.Errorf("select all sharers for user %d: %v", userId, err)
		logE.Print(err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	type user struct {
		Id int64 `json:"id"`
		Name string `json:"name"`
		SharedRecords int64 `json:"shared_records"`
	}
	resBody := struct {
		TotalCount int64 `json:"total_count"`
		Users []user `json:"users"`
	}{}
	for rows.Next() {
		var u user
		if err := rows.Scan(&u.Id, &u.Name, &u.SharedRecords); err != nil {
			err = fmt.Errorf("scan next user: %v", err)
			logE.Print(err)
			replyWithError(w, http.StatusInternalServerError, err)
			return
		}
		resBody.Users = append(resBody.Users, u)
	}
	resBody.TotalCount = int64(len(resBody.Users))
	res, err := json.Marshal(resBody)
	if err != nil {
		err = fmt.Errorf("encode sharers list: %v", err)
		logE.Print(err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	fmt.Fprint(w, string(res))
}
