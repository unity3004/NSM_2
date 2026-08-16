// Package redis owns the connection to Redis and the client every
// internal/ratelimit implementation is built on top of — the same role
// internal/database plays for PostgreSQL. It has no idea what a login
// attempt or a rate-limit dimension is; that separation is what lets
// internal/ratelimit stay focused on abuse-protection policy instead of
// also managing connection lifecycle.
package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/acme/auth-service/internal/config"
)

// NewClient opens a Redis client and verifies it can actually reach the
// server before returning — a misconfigured address should fail at
// startup, not on the first authentication request, the same "fail loud
// and early" choice database.NewPostgresPool already makes.
func NewClient(ctx context.Context, cfg config.RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return client, nil
}
