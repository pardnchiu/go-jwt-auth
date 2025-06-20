package jwtAuth

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

func New(c *Config) (*JWTAuth, error) {
	if c == nil {
		return nil, fmt.Errorf("[Required] Config")
	}

	var logPath string
	var logStdout bool
	var logMaxSize int64
	if c.Log != nil {
		logPath = c.Log.Path
		logStdout = c.Log.Stdout
		logMaxSize = c.Log.MaxSize
	}

	logger, err := newLogger(LoggerConfig{
		Path:    logPath,
		MaxSize: logMaxSize,
		Stdout:  logStdout,
	})
	if err != nil {
		return nil, fmt.Errorf("[Failed] Init logger: %v", err)
	}

	c.Option = validOptionData(c.Option)

	if err := handlePEM(c); err != nil {
		return nil, logger.Error(err, "[Failed] Handle PEM")
	}

	privateKey, publicKey, err := parsePEM(c)
	if err != nil {
		return nil, logger.Error(err, "[Failed] Parse PEM key")
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port),
		Password: c.Redis.Password,
		DB:       c.Redis.DB,
	})

	context := context.Background()

	if _, err := redisClient.Ping(context).Result(); err != nil {
		return nil, logger.Error(err, "[Failed] Connect Redis")
	}

	return &JWTAuth{
		config:  c,
		redis:   redisClient,
		context: context,
		logger:  logger,
		pem: Pem{
			private: privateKey,
			public:  publicKey,
		},
	}, nil
}

func (j *JWTAuth) Close() error {
	return j.redis.Close()
}
