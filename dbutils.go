package main

import (
	"database/sql"
	"fmt"
	"github.com/pkg/errors"
	"testing"
)

func initDB(conf *config) (*sql.DB, error) {
	dbParams := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", conf.DbUser, conf.DbPasswd, conf.DbName)
	db, err := sql.Open("postgres", dbParams)
	if err != nil {
		return nil, errors.Wrap(err, "validate db connection params")
	}
	if err := db.Ping(); err != nil {
		return nil, errors.Wrap(err, "check connection to "+conf.DbName)
	}
	return db, nil
}

func insertUser(db *sql.DB, login string, pass string, name string) error {
	_, err := db.Exec("INSERT INTO users(login, password, name) VALUES($1,$2,$3);",
		login, pass, name)
	return err
}

func insertRecord(db *sql.DB, name string, content string, ownerId int64) error {
	_, err := db.Exec("INSERT INTO records(name, content, owner_id) VALUES($1,$2,$3);",
		name, content, ownerId)
	return err
}

func insertSharing(db *sql.DB, recordId int64, userId int64) error {
	_, err := db.Exec(`INSERT INTO shared(record_id, "to") VALUES($1,$2);`,
		recordId, userId)
	return err
}

func selectAll(db *sql.DB, tableName string, t *testing.T) (res []map[string]interface{}) {
	res = []map[string]interface{}{}
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM %s", tableName))
	cols, _ := rows.Columns()
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPtrs := make([]interface{}, len(cols))
		for i := range columns {
			columnPtrs[i] = &columns[i]
		}
		if err := rows.Scan(columnPtrs...); err != nil {
			t.Fatalf("scan rows from %s", tableName)
		}
		m := make(map[string]interface{})
		for i, colName := range cols {
			val := columnPtrs[i].(*interface{})
			m[colName] = *val
		}
		res = append(res, m)
	}
	return
}
