<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Thin wrapper around the WordPress object cache API for the plugin.
 *
 * All cache operations are scoped to the 'hmdg_security' group so they
 * never collide with core or third-party cache keys. When a persistent
 * object cache backend (Redis, Memcached) is available, data persists
 * across requests; otherwise it lives only for the current PHP process.
 *
 * @since 1.0.0
 */
final class ObjectCacheService
{
    /**
     * WordPress object cache group for all plugin keys.
     */
    private const CACHE_GROUP = 'hmdg_security';

    /**
     * Default cache expiration in seconds (1 hour).
     */
    private const DEFAULT_EXPIRATION = 3600;

    /**
     * Retrieve a value from the object cache.
     *
     * @param string $key Cache key.
     *
     * @return mixed Cached value, or false if the key does not exist.
     */
    public function get(string $key): mixed
    {
        return wp_cache_get($key, self::CACHE_GROUP);
    }

    /**
     * Store a value in the object cache.
     *
     * @param string $key        Cache key.
     * @param mixed  $value      Value to cache.
     * @param int    $expiration Time-to-live in seconds (default 3600).
     *
     * @return bool True on success, false on failure.
     */
    public function set(string $key, mixed $value, int $expiration = self::DEFAULT_EXPIRATION): bool
    {
        return wp_cache_set($key, $value, self::CACHE_GROUP, $expiration);
    }

    /**
     * Atomically add a value only if the key does not already exist.
     *
     * Returns true if the key was created (caller "wins" the lock or the
     * initialisation race), false if it already existed.
     *
     * On Redis-backed object caches this maps to SET NX, which is fully
     * atomic. On the in-memory fallback it is also race-safe within a
     * single PHP process. Used as the primitive for the cron overlap lock.
     *
     * @param string $key        Cache key.
     * @param mixed  $value      Value to add.
     * @param int    $expiration Time-to-live in seconds (default 3600).
     */
    public function add(string $key, mixed $value, int $expiration = self::DEFAULT_EXPIRATION): bool
    {
        return wp_cache_add($key, $value, self::CACHE_GROUP, $expiration);
    }

    /**
     * Remove a value from the object cache.
     *
     * @param string $key Cache key.
     *
     * @return bool True if the key was deleted, false if it did not exist.
     */
    public function delete(string $key): bool
    {
        return wp_cache_delete($key, self::CACHE_GROUP);
    }

    /**
     * Atomically increment a numeric cache value by the given offset.
     *
     * Try wp_cache_incr() first — when backed by Redis or Memcached this
     * is genuinely atomic. If the key does not yet exist (incr returns
     * false), use wp_cache_add() which is also atomic and only succeeds
     * if the key was absent. If add fails (another concurrent request beat
     * us to it), retry the increment. This sequence eliminates the
     * check-then-set race that allowed e.g. 6 login attempts before a
     * 5-attempt lockout under concurrent requests.
     *
     * @param string $key        Cache key.
     * @param int    $offset     Amount to increment by (default 1).
     * @param int    $expiration TTL applied if the key needs initialisation.
     *
     * @return int|false New value on success, or false on failure.
     */
    public function increment(string $key, int $offset = 1, int $expiration = self::DEFAULT_EXPIRATION): int|false
    {
        $result = wp_cache_incr($key, $offset, self::CACHE_GROUP);

        if ($result !== false) {
            return $result;
        }

        // Key does not exist — initialise atomically with wp_cache_add.
        // wp_cache_add only succeeds if the key was absent at the moment
        // of the call, so it is safe under concurrent invocations.
        $added = wp_cache_add($key, $offset, self::CACHE_GROUP, $expiration);

        if ($added) {
            return $offset;
        }

        // Another process initialised it first — increment will now succeed
        return wp_cache_incr($key, $offset, self::CACHE_GROUP);
    }

    /**
     * Whether a key exists in the object cache.
     *
     * Uses the $found reference flag to distinguish a cached false/null
     * from a cache miss.
     *
     * @param string $key Cache key.
     *
     * @return bool True if the key exists, regardless of its value.
     */
    public function exists(string $key): bool
    {
        $found = false;
        wp_cache_get($key, self::CACHE_GROUP, false, $found);

        return $found;
    }
}
