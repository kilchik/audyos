package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const testAddr = "http://127.0.0.1:3042"

func initTestApi() (*Api, *sql.DB) {
	conf := &config{testAddr, "app", "shakira", "audyos_db", "tricky"}
	db, err := initDB(conf)
	if err != nil {
		logE.Fatalf("init db: %v", err)
	}
	return NewApi(db, conf), db
}

func clearAllTables(db *sql.DB) {
	if _, err := db.Exec("TRUNCATE records"); err != nil {
		logE.Fatalf("truncate records: %v", err)
	}
	if _, err := db.Exec("ALTER SEQUENCE records_id_seq RESTART WITH 1"); err != nil {
		logE.Fatalf("reset records_id_seq: %v", err)
	}
	if _, err := db.Exec("TRUNCATE users"); err != nil {
		logE.Fatalf("truncate records: %v", err)
	}
	if _, err := db.Exec("ALTER SEQUENCE users_id_seq RESTART WITH 1"); err != nil {
		logE.Fatalf("reset records_id_seq: %v", err)
	}
	if _, err := db.Exec("TRUNCATE shared"); err != nil {
		logE.Fatalf("truncate records: %v", err)
	}
}

func finalizeTestApi(db *sql.DB) {
	defer db.Close()
}

func TestApi_HandleNewRecord(t *testing.T)  {
	api, db := initTestApi()
	defer finalizeTestApi(db)
	type testCase struct {
		body io.Reader
		expectedCode int
		expectedRecords []map[string]interface{}
	}
	for _, tcase := range []testCase{
		{
			nil,
			http.StatusBadRequest,
			nil,
		},
		{
			strings.NewReader(`{"name": "Queen - Bicycle", "duration": 87, "content": "02bef834dc89341aef"}`),
			http.StatusOK,
			[]map[string]interface{}{
				{
					"id":int64(1),
					"name":"Queen - Bicycle",
					"content": []byte("02bef834dc89341aef"),
					"owner_id": int64(1),
				},
			},
		},
	} {
		clearAllTables(db)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("POST", testAddr+"/records/new", tcase.body)
		api.HandleNewRecord(recorder, req, 1)
		if recorder.Code != tcase.expectedCode {
			t.Fatalf("expected %d; got: %d", tcase.expectedCode, recorder.Code)
		}
		if tcase.expectedRecords == nil {
			continue
		}
		recs := selectAll(db, "records", t)
		if !reflect.DeepEqual(recs, tcase.expectedRecords) {
			t.Fatalf("expected body: %v; got body: %v", tcase.expectedRecords, recs)
		}
	}
}

func TestApi_HandleRegistration(t *testing.T) {
	api, db := initTestApi()
	defer finalizeTestApi(db)
	type testCase struct {
		body io.Reader
		expectedCode int
		expectedRecords []map[string]interface{}
	}
	for _, tcase := range []testCase{
		{
			nil,
			http.StatusBadRequest,
			nil,
		},
		{
			strings.NewReader(`{"login": "anton21", "password": "heyyou1", "name": "Anton"}`),
			http.StatusOK,
			[]map[string]interface{}{
				{
					"id":int64(1),
					"login":"anton21",
					"password": "heyyou1",
					"name": "Anton",
				},
			},
		},
	} {
		clearAllTables(db)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http://127.0.0.1:3042/register", tcase.body)
		api.HandleRegistration(recorder, req)
		if recorder.Code != tcase.expectedCode {
			t.Fatalf("expected %d; got: %d", tcase.expectedCode, recorder.Code)
		}
		if tcase.expectedRecords == nil {
			continue
		}
		recs := selectAll(db, "users", t)
		if !reflect.DeepEqual(recs, tcase.expectedRecords) {
			t.Fatalf("expected body: %v; got body: %v", tcase.expectedRecords, recs)
		}
	}
}

func TestApi_HandleAuthorization(t *testing.T) {
	api, db := initTestApi()
	defer finalizeTestApi(db)
	type testCase struct {
		body io.Reader
		expectedCode int
		expectedKeysInBody []string
	}
	for _, tcase := range []testCase{
		{
			nil,
			http.StatusBadRequest,
			nil,
		},
		// Existing user
		{
			strings.NewReader(`{"login": "user1", "password": "123"}`),
			http.StatusOK,
			[]string{
				"access_token",
			},
		},
		// User does not exist
		{
			strings.NewReader(`{"login": "user2", "password": "123"}`),
			http.StatusForbidden,
			nil,
		},
		// Invalid password
		{
			strings.NewReader(`{"login": "user1", "password": "qwerty"}`),
			http.StatusForbidden,
			nil,
		},

	} {
		clearAllTables(db)
		recorder := httptest.NewRecorder()

		// Need to register test user first
		req := httptest.NewRequest("POST", testAddr+"/register",
			strings.NewReader(`{"login": "user1", "password": "123", "name": "Anton"}`))
		api.HandleRegistration(recorder, req)

		req = httptest.NewRequest("POST", testAddr+"/auth", tcase.body)
		api.HandleAuthorization(recorder, req)
		if recorder.Code != tcase.expectedCode {
			t.Fatalf("expected %d; got: %d", tcase.expectedCode, recorder.Code)
		}
		if tcase.expectedKeysInBody == nil {
			continue
		}
		bodyBytes, err := ioutil.ReadAll(recorder.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			t.Fatalf("decode response body: %v", err)
		}
		for _, k := range tcase.expectedKeysInBody {
			if _, ok := body[k]; !ok {
				t.Fatalf("expected key %q in body", k)
			}
		}
	}
}

func TestApi_HandleShareRecord(t *testing.T) {
	api, db := initTestApi()
	defer finalizeTestApi(db)
	type testCase struct {
		body io.Reader
		expectedCode int
		expectedRecords []map[string]interface{}
	}
	for _, tcase := range []testCase{
		{
			nil,
			http.StatusBadRequest,
			nil,
		},
		{
			strings.NewReader(`{"record_id": 1, "user_id": 2}`),
			http.StatusOK,
			[]map[string]interface{}{
				{
					"record_id": int64(1),
					"to": int64(2),
				},
			},
		},
		// Test user does not have record with id 3
		{
			strings.NewReader(`{"record_id": 3, "user_id": 2}`),
			http.StatusNotAcceptable,
			nil,
		},
	} {
		clearAllTables(db)
		recorder := httptest.NewRecorder()

		// Need to create record of user 1 first to be able to share it
		req := httptest.NewRequest("POST", testAddr+"/records/new",
			strings.NewReader(`{"name": "song1", "duration": 98, "content": "123"}`))
		api.HandleNewRecord(recorder, req, 1)

		req = httptest.NewRequest("POST", testAddr+"/records/share", tcase.body)
		api.HandleShareRecord(recorder, req, 1)
		if recorder.Code != tcase.expectedCode {
			t.Fatalf("expected %d; got: %d", tcase.expectedCode, recorder.Code)
		}
		if tcase.expectedRecords == nil {
			continue
		}
		recs := selectAll(db, "shared", t)
		if !reflect.DeepEqual(recs, tcase.expectedRecords) {
			t.Fatalf("expected body: %v; got body: %v", tcase.expectedRecords, recs)
		}
	}
}

func TestApi_HandleUnshareRecord(t *testing.T) {
	api, db := initTestApi()
	defer finalizeTestApi(db)
	type testCase struct {
		body io.Reader
		expectedCode int
		expectedRecords []map[string]interface{}
	}
	const testUserId = 1
	for _, tcase := range []testCase{
		{
			nil,
			http.StatusBadRequest,
			nil,
		},
		{
			strings.NewReader(`{"record_id": 1, "user_id": 2}`),
			http.StatusOK,
			[]map[string]interface{}{},
		},
		// Test user does not have record with id 3
		{
			strings.NewReader(`{"record_id": 3, "user_id": 2}`),
			http.StatusNotAcceptable,
			nil,
		},
	} {
		clearAllTables(db)
		recorder := httptest.NewRecorder()

		// Need to create record of user 1 first to be able to share it
		req := httptest.NewRequest("POST", testAddr+"/records/new",
			strings.NewReader(`{"name": "song1", "duration": 98, "content": "123"}`))
		api.HandleNewRecord(recorder, req, testUserId)

		// Then need to share record
		req = httptest.NewRequest("POST", testAddr+"/records/share",
			strings.NewReader(`{"record_id": 1, "user_id": 2}`))
		api.HandleShareRecord(recorder, req, testUserId)

		req = httptest.NewRequest("POST", testAddr+"/records/unshare", tcase.body)
		api.HandleUnshareRecord(recorder, req, testUserId)

		if recorder.Code != tcase.expectedCode {
			t.Fatalf("expected %d; got: %d", tcase.expectedCode, recorder.Code)
		}
		if tcase.expectedRecords == nil {
			continue
		}
		recs := selectAll(db, "shared", t)
		if !reflect.DeepEqual(recs, tcase.expectedRecords) {
			t.Fatalf("expected body: %v; got body: %v", tcase.expectedRecords, recs)
		}
	}
}

// TODO: extract URL prefix to constant
func TestApi_HandleRecordsList(t *testing.T) {
	api, db := initTestApi()
	defer finalizeTestApi(db)
	type testCase struct {
		urlParams string
		expectedCode int
		expectedJson []byte
	}
	const testUserId = 1
	initTables := func() {
		check(insertUser(db, "superdave", "123", "David"), t)
		check(insertUser(db, "ritchie1", "qwerty", "Richard"), t)
		check(insertRecord(db, "Time", "abc34def", 1), t)
		check(insertRecord(db, "Catch The Rainbow", "sdf32sg", 2), t)
		check(insertRecord(db, "Hey You", "sdf32sg", 1), t)
		check(insertSharing(db, 1, 2), t)
		check(insertSharing(db, 2, 1), t)
	}
	// TODO: test of sorting by owner
	for _, tcase := range []testCase{
		{
			urlParams:"?limit=10&offset=0&sort_by=record",
			expectedCode:http.StatusOK,
			expectedJson: []byte(`
{
	"total_count": 3,
	"records": [
		{
			"id": 3,
			"name": "Hey You",
			"is_owner": true,
			"owner_id": 1,
			"owner_name": "David",
			"shared_to": []
		},
		{
			"id": 1,
			"name": "Time",
			"is_owner": true,
			"owner_id": 1,
			"owner_name": "David",
			"shared_to": [
				{
					"id": 2,
					"name": "Richard"
				}
			]
		},
		{
			"id": 2,
			"name": "Catch The Rainbow",
			"is_owner": false,
			"owner_id": 2,
			"owner_name": "Richard",
			"shared_to": [
				{
					"id": 1,
					"name": "David"
				}
			]
		}
	]
}
`),
		},
	} {
		clearAllTables(db)
		initTables()
		recorder := httptest.NewRecorder()

		req := httptest.NewRequest("GET", testAddr+tcase.urlParams, nil)
		api.HandleRecordsList(recorder, req, testUserId)

		if recorder.Code != tcase.expectedCode {
			t.Fatalf("expected %d; got: %d", tcase.expectedCode, recorder.Code)
		}
		bodyBytes, err := ioutil.ReadAll(recorder.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		fmt.Println(string(bodyBytes))
		var body, bodyExpected map[string]interface{}
		check(json.Unmarshal(bodyBytes, &body), t)
		check(json.Unmarshal(tcase.expectedJson, &bodyExpected), t)
		if !reflect.DeepEqual(body, bodyExpected) {
			t.Fatalf("expected body: %v; got body: %v", bodyExpected, body)
		}
	}
}

func TestApi_HandleSharersList(t *testing.T) {
	api, db := initTestApi()
	defer finalizeTestApi(db)
	type testCase struct {
		urlParams string
		expectedCode int
		expectedJson []byte
	}
	const testUserId = 1
	initTables := func() {
		check(insertUser(db, "superdave", "123", "David"), t)
		check(insertUser(db, "ritchie1", "qwerty", "Richard"), t)
		check(insertRecord(db, "Time", "abc34def", 1), t)
		check(insertRecord(db, "Catch The Rainbow", "sdf32sg", 2), t)
		check(insertRecord(db, "Hey You", "sdf32sg", 1), t)
		check(insertSharing(db, 1, 2), t)
		check(insertSharing(db, 2, 1), t)
		check(insertSharing(db, 3, 2), t)
	}
	for _, tcase := range []testCase{
		{
			urlParams:"?limit=10&offset=0",
			expectedCode:http.StatusOK,
			expectedJson: []byte(`
{
	"total_count": 2,
	"users": [
		{
			"id": 1,
			"name": "David",
			"shared_records": 2 
		},
		{
			"id": 2,
			"name": "Richard",
			"shared_records": 1
		}
	]
}
`),
		},
	} {
		clearAllTables(db)
		initTables()
		recorder := httptest.NewRecorder()

		req := httptest.NewRequest("GET", testAddr+tcase.urlParams, nil)
		api.HandleSharersList(recorder, req, testUserId)

		if recorder.Code != tcase.expectedCode {
			t.Fatalf("expected %d; got: %d", tcase.expectedCode, recorder.Code)
		}
		bodyBytes, err := ioutil.ReadAll(recorder.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var body, bodyExpected map[string]interface{}
		check(json.Unmarshal(bodyBytes, &body), t)
		check(json.Unmarshal(tcase.expectedJson, &bodyExpected), t)
		if !reflect.DeepEqual(body, bodyExpected) {
			t.Fatalf("expected body: %v; got body: %v", bodyExpected, body)
		}
	}
}

func check(err error, t *testing.T) {
	if err != nil {
		t.Fatalf(err.Error())
	}
}