<?php
declare(strict_types=1);

function receptionist_password_file(): string
{
    $configuredPath = getenv('RECEPTIONIST_PASSWORD_FILE');
    if ($configuredPath !== false && trim($configuredPath) !== '') {
        return $configuredPath;
    }

    return dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . 'poh-private' . DIRECTORY_SEPARATOR . 'receptionist-password.hash';
}

function receptionist_saved_password_hash(): ?string
{
    $path = receptionist_password_file();
    if (!is_file($path)) {
        return null;
    }

    $hash = trim((string) file_get_contents($path));
    if ($hash === '' || (password_get_info($hash)['algo'] ?? null) === null) {
        throw new RuntimeException('The saved receptionist credential is invalid.');
    }

    return $hash;
}

function receptionist_password_is_configured(): bool
{
    try {
        if (receptionist_saved_password_hash() !== null) {
            return true;
        }
    } catch (Throwable $error) {
        return true;
    }

    $initialPassword = getenv('RECEPTIONIST_PASSWORD');
    return $initialPassword !== false && trim($initialPassword) !== '';
}

function receptionist_password_matches(string $password): bool
{
    $savedHash = receptionist_saved_password_hash();
    if ($savedHash !== null) {
        return password_verify($password, $savedHash);
    }

    $initialPassword = getenv('RECEPTIONIST_PASSWORD');
    return $initialPassword !== false && trim($initialPassword) !== '' && hash_equals($initialPassword, $password);
}

function receptionist_save_password(string $password): void
{
    $path = receptionist_password_file();
    $directory = dirname($path);

    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create the credential storage directory.');
    }

    $file = fopen($path, 'c+');
    if ($file === false) {
        throw new RuntimeException('Unable to open credential storage.');
    }

    try {
        if (!flock($file, LOCK_EX)) {
            throw new RuntimeException('Unable to lock credential storage.');
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        if ($hash === false) {
            throw new RuntimeException('Unable to hash the new password.');
        }

        rewind($file);
        if (!ftruncate($file, 0) || fwrite($file, $hash) === false || !fflush($file)) {
            throw new RuntimeException('Unable to save the new password.');
        }

        @chmod($path, 0600);
    } finally {
        flock($file, LOCK_UN);
        fclose($file);
    }
}

function receptionist_reset_state_path(): string
{
    $configuredPath = getenv('RECEPTIONIST_RESET_FILE');
    if ($configuredPath !== false && trim($configuredPath) !== '') {
        return $configuredPath;
    }

    return dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . 'poh-private' . DIRECTORY_SEPARATOR . 'receptionist-reset.json';
}

function with_receptionist_reset_state(callable $operation, bool $write = false): mixed
{
    $path = receptionist_reset_state_path();
    $directory = dirname($path);

    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create the reset storage directory.');
    }

    $file = fopen($path, 'c+');
    if ($file === false) {
        throw new RuntimeException('Unable to open reset storage.');
    }

    try {
        if (!flock($file, LOCK_EX)) {
            throw new RuntimeException('Unable to lock reset storage.');
        }

        rewind($file);
        $contents = stream_get_contents($file);
        $state = $contents === '' ? [] : json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($state)) {
            throw new RuntimeException('Reset storage has an invalid format.');
        }

        $result = $operation($state);

        if ($write) {
            $encoded = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            rewind($file);
            if (!ftruncate($file, 0) || fwrite($file, $encoded) === false || !fflush($file)) {
                throw new RuntimeException('Unable to save reset storage.');
            }
            @chmod($path, 0600);
        }

        return $result;
    } finally {
        flock($file, LOCK_UN);
        fclose($file);
    }
}

function receptionist_create_reset_token(): ?string
{
    $token = bin2hex(random_bytes(32));
    $tokenHash = password_hash($token, PASSWORD_DEFAULT);
    if ($tokenHash === false) {
        throw new RuntimeException('Unable to create a password reset token.');
    }

    return with_receptionist_reset_state(static function (array &$state) use ($token, $tokenHash): ?string {
        $now = time();
        $windowStart = (int) ($state['window_started_at'] ?? 0);
        $requestCount = (int) ($state['request_count'] ?? 0);

        if ($windowStart === 0 || $now - $windowStart >= 900) {
            $windowStart = $now;
            $requestCount = 0;
        }
        if ($requestCount >= 3) {
            return null;
        }

        $state['window_started_at'] = $windowStart;
        $state['request_count'] = $requestCount + 1;
        $state['token_hash'] = $tokenHash;
        $state['expires_at'] = $now + 1800;
        return $token;
    }, true);
}

function receptionist_reset_token_is_valid(string $token): bool
{
    if (preg_match('/^[a-f0-9]{64}$/D', $token) !== 1) {
        return false;
    }

    return with_receptionist_reset_state(static function (array &$state) use ($token): bool {
        return (int) ($state['expires_at'] ?? 0) > time()
            && isset($state['token_hash'])
            && password_verify($token, (string) $state['token_hash']);
    });
}

function receptionist_consume_reset_token(string $token, string $password): bool
{
    if (preg_match('/^[a-f0-9]{64}$/D', $token) !== 1) {
        return false;
    }

    return with_receptionist_reset_state(static function (array &$state) use ($token, $password): bool {
        if ((int) ($state['expires_at'] ?? 0) <= time()
            || !isset($state['token_hash'])
            || !password_verify($token, (string) $state['token_hash'])) {
            return false;
        }

        receptionist_save_password($password);
        unset($state['token_hash'], $state['expires_at']);
        return true;
    }, true);
}

function receptionist_clear_reset_token(): void
{
    with_receptionist_reset_state(static function (array &$state): void {
        unset($state['token_hash'], $state['expires_at']);
    }, true);
}