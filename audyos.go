package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"github.com/mitchellh/mapstructure"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	logE *log.Logger
	logI *log.Logger
)

type handler struct {
	db       *sql.DB
	conf     *config
	doHandle func(w http.ResponseWriter, r *http.Request, db *sql.DB, conf *config)
}

func newHandler(f func(w http.ResponseWriter, r *http.Request, db *sql.DB, conf *config), db *sql.DB, conf *config) *handler {
	return &handler{doHandle: f, db: db, conf: conf}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.doHandle(w, r, h.db, h.conf)
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

func main() {
	logE = log.New(os.Stderr, "[E] ", 0)
	logI = log.New(os.Stderr, "[I] ", 0)

	logI.Println("started :)")

	confPath := flag.String("config", "audyos.conf", "path to configuration file")
	flag.Parse()
	if confPath == nil {
		logE.Fatalf("invalid configuration path argument")
	}

	conf, err := readConfig(*confPath)
	if err != nil {
		logE.Fatalf("read config: %v", err)
	}

	dbParams := fmt.Sprintf("user=%s password=%s dbname=%s  sslmode=disable", conf.DbUser, conf.DbPasswd, conf.DbName)
	db, err := sql.Open("postgres", dbParams)
	if err != nil {
		logE.Fatalf("validate db connection params: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		logE.Fatalf("check connection to %q: %v", conf.DbName, err)
	}

	http.Handle("/register", newHandler(handleRegistration, db, conf))
	http.Handle("/auth", newHandler(handleAuthorization, db, conf))
	http.Handle("/records/new", newAuthHandler(handleNewRecord, db, conf))
	http.Handle("/records/share", newAuthHandler(handleShareRecord, db, conf))
	http.Handle("/records/unshare", newAuthHandler(handleUnshareRecord, db, conf))
	http.Handle("/records", newAuthHandler(handleRecordsList, db, conf))
	http.Handle("/users/sharers", newAuthHandler(handleSharersList, db, conf))

	if err := http.ListenAndServe(conf.Listen, nil); err != nil {
		logE.Fatalf("listen and serve: %v", err)
	}
}

func handleRegistration(w http.ResponseWriter, r *http.Request, db *sql.DB, _ *config) {
	var reqBody struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		replyWithError(w, http.StatusBadRequest, fmt.Errorf("decode request body: %v", err))
		return
	}
	if _, err := db.Exec("INSERT INTO users(login, password, name) VALUES($1,$2,$3);",
		reqBody.Login, reqBody.Password, reqBody.Name); err != nil {
		err = fmt.Errorf("insert new user: %v", err)
		logE.Print(err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
}

// TODO: consider using refresh token
// TODO: wrapper for logging requests and responses (maybe x-req-id?)
func handleAuthorization(w http.ResponseWriter, r *http.Request, db *sql.DB, conf *config) {
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
	// TODO: check for sql injection
	rows, err := db.Query("SELECT id FROM users WHERE login=$1 AND password=$2", reqBody.Login, reqBody.Password)
	if err != nil {
		err = fmt.Errorf("select user with login %q: %v", reqBody.Login, err)
		logE.Print(err)
		replyWithError(w, http.StatusUnauthorized, err)
		return
	}
	rows.Next()
	var userId int64
	if err := rows.Scan(&userId); err != nil {
		err = fmt.Errorf("retrieve user id from db: %v", err)
		replyWithError(w, http.StatusUnauthorized, err)
		return
	}
	claimsMap := make(map[string]interface{})
	if err := mapstructure.Decode(&tokenClaims{
		Login:  reqBody.Login,
		UserId: userId,
		Exp:    time.Now().Add(24 * time.Hour).Unix(),
	}, &claimsMap); err != nil {
		err = fmt.Errorf("encode token claims: %v", err)
		replyWithError(w, http.StatusUnauthorized, err)
		return
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), jwt.MapClaims(claimsMap))
	logI.Printf("conf.JwtSignKey: %v", conf.JwtSignKey)
	tokenString, err := token.SignedString([]byte(conf.JwtSignKey))
	logI.Printf("generated token string: %v", tokenString)
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

func handleNewRecord(w http.ResponseWriter, r *http.Request, userId int64, db *sql.DB, _ *config) {
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
	if _, err := db.Exec("INSERT INTO records(name, content, owner_id) VALUES($1,$2,$3);",
		reqBody.Name, reqBody.Content, userId); err != nil {
		err = fmt.Errorf("insert new record: %v", err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
}

func handleShareRecord(w http.ResponseWriter, r *http.Request, userId int64, db *sql.DB, _ *config) {
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
	qres, err := db.Exec(`
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

func handleUnshareRecord(w http.ResponseWriter, r *http.Request, userId int64, db *sql.DB, _ *config) {
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
	qres, err := db.Exec(`
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

func handleSharersList(w http.ResponseWriter, r *http.Request, userId int64, db *sql.DB, _ *config) {
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
	rows, err := db.Query(`
SELECT DISTINCT R.owner_id,
                U.name,
                COUNT(DISTINCT R.id)
FROM ( SHARED S
       JOIN records R ON S.record_id=R.id
       JOIN users U ON R.owner_id=U.id)
GROUP BY R.owner_id,
         U.name
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

func handleRecordsList(w http.ResponseWriter, r *http.Request, userId int64, db *sql.DB, _ *config) {
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
	rows, err := db.Query(`
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
         $4,
         rec_id
`, userId, limit, offset, orderSuffix)
	if err != nil {
		err = fmt.Errorf("select all records for user %d: %v", userId, err)
		logE.Print(err)
		replyWithError(w, http.StatusInternalServerError, err)
		return
	}
	for rows.Next() {
		var rec record
		var sharedToId int64
		var sharedToName string
		if err := rows.Scan(&rec.Id, &rec.Name, &rec.IsOwner, &rec.OwnerId, &rec.OwnerName, &sharedToId, &sharedToName); err != nil {
			err = fmt.Errorf("retrieve record from db for user %d: %v", rec.OwnerId, err)
			logE.Print(err)
			replyWithError(w, http.StatusInternalServerError, err)
			return
		}
		if len(resBody.Records) > 0 && resBody.Records[len(resBody.Records)-1].Id == rec.Id {
			resBody.Records[len(resBody.Records)-1].SharedTo = append(resBody.Records[len(resBody.Records)-1].SharedTo,
				shared{sharedToId, sharedToName})
		} else {
			rec.SharedTo = []shared{}
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
