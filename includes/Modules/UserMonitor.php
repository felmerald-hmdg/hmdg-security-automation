<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\SecurityConfig;
use HMDG\Security\SecurityEvent;
use HMDG\Security\Services\AlertService;
use HMDG\Security\Services\LogService;

/**
 * Monitors user account lifecycle events and fires security alerts
 * when sensitive operations occur: new administrator creation, role
 * escalation, user deletion, and admin password resets.
 *
 * Also enforces a reserved-username policy to prevent registration
 * of common attack-target usernames (admin, administrator, root, etc.).
 *
 * All timestamps use Europe/London timezone for consistent audit trails
 * across multi-server environments.
 *
 * @since 1.0.0
 */
final class UserMonitor
{
    /** Module identifier used in log entries. */
    private const MODULE = 'UserMonitor';

    /**
     * Register all WordPress hooks for user monitoring.
     *
     * @param SecurityConfig $config       Immutable plugin configuration.
     * @param AlertService   $alertService Alert dispatch service.
     * @param LogService     $logService   Structured logging service.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly AlertService $alertService,
        private readonly LogService $logService,
    ) {
        $this->registerHooks();
    }

    /**
     * Attach all WordPress action and filter hooks for user monitoring.
     */
    private function registerHooks(): void
    {
        // Alert on new user registration
        add_action('user_register', [$this, 'handleUserRegister'], 10, 1);

        // Alert on role change to administrator
        add_action('set_user_role', [$this, 'handleSetUserRole'], 10, 3);

        // Alert on user deletion
        add_action('delete_user', [$this, 'handleDeleteUser'], 10, 2);

        // Alert on admin password reset
        add_action('after_password_reset', [$this, 'handlePasswordReset'], 10, 2);

        // Block reserved usernames via validation
        add_filter('validate_username', [$this, 'validateUsername'], 10, 2);

        // Block reserved usernames via illegal logins list
        add_filter('illegal_user_logins', [$this, 'getIllegalUserLogins'], 10, 1);
    }

    // ── 1. New User Registration ──────────────────────────────────────

    /**
     * Fire an alert when a new administrator account is created.
     *
     * Runs on the 'user_register' hook immediately after a new user is
     * inserted into the database. Only alerts when the new user has the
     * administrator role — subscriber and other role registrations are
     * logged but do not trigger email alerts.
     *
     * @param int $userId The ID of the newly registered user.
     */
    public function handleUserRegister(int $userId): void
    {
        $user = get_userdata($userId);

        if ($user === false) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'user_register fired but user not found',
                context: ['user_id' => $userId],
            );

            return;
        }

        $roles = $user->roles;

        $this->logService->info(
            module: self::MODULE,
            message: 'New user registered',
            context: [
                'user_id' => $userId,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'roles' => $roles,
            ],
        );

        if (!in_array('administrator', $roles, true)) {
            return;
        }

        $timestamp = $this->getTimestamp();
        $ip = $this->getClientIp();
        $siteUrl = get_site_url();

        $context = [
            'source' => $ip,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'role' => 'administrator',
            'ip' => $ip,
            'timestamp' => $timestamp,
            'site_url' => $siteUrl,
            'recommendation' => 'Verify this administrator account was created intentionally.',
        ];

        $this->logService->warning(
            module: self::MODULE,
            message: 'New administrator account created',
            context: $context,
        );

        $this->alertService->send(
            event: SecurityEvent::NewAdminUser,
            context: $context,
        );
    }

    // ── 2. Role Change to Administrator ───────────────────────────────

    /**
     * Fire an alert when a user's role is escalated to administrator.
     *
     * Runs on the 'set_user_role' hook which fires whenever a user's
     * role is changed. Only alerts when the new role is 'administrator'
     * and the user was not previously an administrator, preventing
     * duplicate alerts when an admin's role is re-saved unchanged.
     *
     * @param int      $userId   The ID of the user whose role changed.
     * @param string   $role     The new role assigned to the user.
     * @param string[] $oldRoles Array of the user's previous roles.
     */
    public function handleSetUserRole(int $userId, string $role, array $oldRoles): void
    {
        if ($role !== 'administrator') {
            return;
        }

        if (in_array('administrator', $oldRoles, true)) {
            return;
        }

        $user = get_userdata($userId);

        if ($user === false) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'set_user_role fired but user not found',
                context: ['user_id' => $userId, 'new_role' => $role],
            );

            return;
        }

        $timestamp = $this->getTimestamp();
        $ip = $this->getClientIp();
        $siteUrl = get_site_url();
        $actorName = $this->getCurrentActorName();

        $context = [
            'source' => $ip,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'old_roles' => implode(separator: ', ', array: $oldRoles),
            'new_role' => $role,
            'performed_by' => $actorName,
            'ip' => $ip,
            'timestamp' => $timestamp,
            'site_url' => $siteUrl,
            'recommendation' => 'Verify this role escalation was authorized.',
        ];

        $this->logService->critical(
            module: self::MODULE,
            message: 'User role escalated to administrator',
            context: $context,
        );

        $this->alertService->send(
            event: SecurityEvent::RoleEscalation,
            context: $context,
        );
    }

    // ── 3. User Deletion ──────────────────────────────────────────────

    /**
     * Fire an alert when a user account is deleted.
     *
     * Runs on the 'delete_user' hook which fires before the user is
     * actually removed from the database. This allows us to retrieve
     * the user's data for the alert before it is lost.
     *
     * @param int      $userId   The ID of the user being deleted.
     * @param int|null $reassign The ID of the user to whom content is reassigned, or null.
     */
    public function handleDeleteUser(int $userId, ?int $reassign): void
    {
        $user = get_userdata($userId);

        if ($user === false) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'delete_user fired but user not found',
                context: ['user_id' => $userId],
            );

            return;
        }

        $roles = $user->roles;
        $roleLabel = $roles !== [] ? implode(separator: ', ', array: $roles) : 'none';

        $timestamp = $this->getTimestamp();
        $ip = $this->getClientIp();
        $siteUrl = get_site_url();
        $actorName = $this->getCurrentActorName();

        $context = [
            'source' => $ip,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'role' => $roleLabel,
            'deleted_by' => $actorName,
            'reassigned_to' => $reassign !== null ? (string) $reassign : 'none',
            'ip' => $ip,
            'timestamp' => $timestamp,
            'site_url' => $siteUrl,
            'recommendation' => 'Verify this user deletion was intentional.',
        ];

        $this->logService->warning(
            module: self::MODULE,
            message: 'User account deleted',
            context: $context,
        );

        $this->alertService->send(
            event: SecurityEvent::UserDeleted,
            context: $context,
        );
    }

    // ── 4. Admin Password Reset ───────────────────────────────────────

    /**
     * Fire an alert when an administrator's password is reset.
     *
     * Password resets for administrator accounts are a potential
     * escalation vector — a compromised email account could be used
     * to reset an admin password and gain full site access. This
     * handler fires SecurityEvent::RoleEscalation to ensure maximum
     * visibility.
     *
     * The new password is NEVER logged or included in the alert context.
     *
     * @param \WP_User $user    The user whose password was reset.
     * @param string   $newPass The new password (NEVER logged — parameter exists only for hook signature).
     */
    public function handlePasswordReset(\WP_User $user, string $newPass): void
    {
        if (!in_array('administrator', $user->roles, true)) {
            return;
        }

        $timestamp = $this->getTimestamp();
        $ip = $this->getClientIp();
        $siteUrl = get_site_url();

        $context = [
            'source' => $ip,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'ip' => $ip,
            'timestamp' => $timestamp,
            'site_url' => $siteUrl,
            'recommendation' => 'Verify this administrator password reset was authorized.',
        ];

        $this->logService->warning(
            module: self::MODULE,
            message: 'Administrator password reset detected',
            context: $context,
        );

        $this->alertService->send(
            event: SecurityEvent::RoleEscalation,
            context: $context,
        );
    }

    // ── 5. Block Reserved Usernames ───────────────────────────────────

    /**
     * Reject reserved usernames during registration and profile updates.
     *
     * Runs on the 'validate_username' filter. If the username (lowercased)
     * matches any entry in the reserved list, the filter returns false to
     * prevent the username from being accepted.
     *
     * @param bool   $valid    Whether the username passed prior validation checks.
     * @param string $username The username being validated.
     *
     * @return bool False if the username is reserved, otherwise the original validity.
     */
    public function validateUsername(bool $valid, string $username): bool
    {
        if (!$valid) {
            return false;
        }

        $normalised = strtolower(trim($username));

        if (in_array($normalised, $this->config->reservedUsernames, true)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Reserved username registration blocked',
                context: [
                    'username' => $username,
                    'ip' => $this->getClientIp(),
                ],
            );

            return false;
        }

        return true;
    }

    /**
     * Provide the reserved usernames list to WordPress's illegal logins filter.
     *
     * Runs on the 'illegal_user_logins' filter. Returns the configured
     * reserved usernames array, which WordPress uses to block registration
     * attempts with these usernames at the core level.
     *
     * @param string[] $illegalLogins Existing illegal logins from other filters.
     *
     * @return string[] Merged array of illegal logins including reserved usernames.
     */
    public function getIllegalUserLogins(array $illegalLogins = []): array
    {
        return array_unique([...$illegalLogins, ...$this->config->reservedUsernames]);
    }

    // ── Private Helpers ───────────────────────────────────────────────

    /**
     * Retrieve the client IP address from the server environment.
     *
     * Uses REMOTE_ADDR exclusively. X-Forwarded-For is not trusted because
     * it is trivially spoofable by clients. WP Engine and similar managed
     * hosts set REMOTE_ADDR to the real client IP behind their reverse proxy.
     *
     * The returned value is sanitised to contain only valid IP characters.
     *
     * @return string The sanitised client IP address, or '0.0.0.0' if unavailable.
     */
    private function getClientIp(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Sanitise: allow only valid IP address characters (digits, dots, colons for IPv6, hex letters)
        $sanitised = preg_replace('/[^0-9a-fA-F.:\/]/', '', $ip);

        if ($sanitised === '' || $sanitised === null) {
            return '0.0.0.0';
        }

        // Validate as a proper IP address
        if (filter_var($sanitised, \FILTER_VALIDATE_IP) === false) {
            return '0.0.0.0';
        }

        return $sanitised;
    }

    /**
     * Get the display name of the currently logged-in user.
     *
     * Used to attribute administrative actions (role changes, deletions)
     * to a specific actor in alert context. Returns 'Unknown/System' when
     * no user is authenticated (e.g. WP-CLI or cron-triggered events).
     *
     * @return string The current user's display name or 'Unknown/System'.
     */
    private function getCurrentActorName(): string
    {
        $currentUser = wp_get_current_user();

        if ($currentUser->ID === 0) {
            return 'Unknown/System';
        }

        return $currentUser->display_name;
    }

    /**
     * Generate a formatted timestamp in Europe/London timezone.
     *
     * All security events use this format for consistent audit trails
     * across alerts and log entries.
     *
     * @return string Formatted timestamp (e.g. "15 Apr 2026 14:30:00 BST").
     */
    private function getTimestamp(): string
    {
        return (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'd M Y H:i:s T');
    }
}
