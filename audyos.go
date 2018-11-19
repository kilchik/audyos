package main

import (
	"flag"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
)

var (
	logE *log.Logger
	logI *log.Logger
)

func init()  {
	logE = log.New(os.Stderr, "[E] ", 0)
	logI = log.New(os.Stderr, "[I] ", 0)
}

func main() {
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

	db, err := initDB(conf)
	if err != nil {
		logE.Fatalf("init db: %v", err)
	}
	defer db.Close()

	api := NewApi(db, conf)
	http.Handle("/v1/users/register", api.Handler(api.HandleRegistration))
	http.Handle("/v1/users/auth", api.Handler(api.HandleAuthorization))
	http.Handle("/v1/users/sharers", api.HandlerWithAuth(api.HandleSharersList))
	http.Handle("/v1/records/new", api.HandlerWithAuth(api.HandleNewRecord))
	http.Handle("/v1/records/share", api.HandlerWithAuth(api.HandleShareRecord))
	http.Handle("/v1/records/unshare", api.HandlerWithAuth(api.HandleUnshareRecord))
	http.Handle("/v1/records", api.HandlerWithAuth(api.HandleRecordsList))

	if err := http.ListenAndServe(conf.Listen, nil); err != nil {
		logE.Fatalf("listen and serve: %v", err)
	}
}
