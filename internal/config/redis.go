package config

import (
	"os"
	"strconv"
	"time"
)

type RedisConfig struct {
	Host           string
	Port           string
	Password       string
	DB             int
	PoolSize       int
	MinIdleConns   int
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
}

func LoadRedisConfig() RedisConfig {
	db, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	poolSize, _ := strconv.Atoi(getEnv("REDIS_POOL_SIZE", "10"))
	minIdle, _ := strconv.Atoi(getEnv("REDIS_MIN_IDLE_CONNS", "5"))

	return RedisConfig{
		Host:         getEnv("REDIS_HOST", "localhost"),
		Port:         getEnv("REDIS_PORT", "6379"),
		Password:     getEnv("REDIS_PASSWORD", ""),
		DB:           db,
		PoolSize:     poolSize,
		MinIdleConns: minIdle,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
