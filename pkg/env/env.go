package env

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/umohsamuel/authentication-authorization/pkg/util"
)

type AuthenticationEV struct {
	JWT_SECRET string
}

type DatabaseEV struct {
	PG_PORT      int
	DATABASE_URL string
}

type EnvironmentVariables struct {
	Port                  string
	ProductionEnvironment bool
	ClientDomain          string
	ProjectName           string
	Authentication        AuthenticationEV
	Database              DatabaseEV
}

func loadEnv() {
	rootPath := util.GetRootPath()
	err := godotenv.Load(rootPath + `/.env`)

	if err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}
}

func LoadEnvironmentVariables() *EnvironmentVariables {
	loadEnv()

	return &EnvironmentVariables{
		Port:                  getEnv("PORT", ":5000"),
		ProductionEnvironment: getEnvAsBool("PRODUCTION_ENVIRONMENT", false),
		ClientDomain:          getEnv("CLIENT_DOMAIN", "localhost"),
		ProjectName:           getEnv("PROJECT_NAME", "eba"),
		Authentication: AuthenticationEV{
			JWT_SECRET: getEnvOrError("JWT_SECRET"),
		},
		Database: DatabaseEV{
			PG_PORT:      getEnvAsInt("PG_PORT", 5433),
			DATABASE_URL: getEnvOrError("DATABASE_URL"),
		},
	}
}

func getEnvOrError(key string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	panic("Environment variable " + key + " not set")
}

func getEnv(key string, fallback string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	value, exist := os.LookupEnv(key)
	if exist {
		valueInt, err := strconv.Atoi(value)
		if err != nil {
			log.Panicf("Environment variable \"%v\" not set properly", key)
		}
		return valueInt
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	value, exist := os.LookupEnv(key)
	if exist {
		valueBool, err := strconv.ParseBool(value)
		if err != nil {
			log.Panicf("Environment variable \"%v\" not set properly", key)
		}
		return valueBool
	}
	return fallback
}
