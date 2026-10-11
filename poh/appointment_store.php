<?php
declare(strict_types=1);

function appointment_store_path(): string
{
    $configuredPath = getenv('APPOINTMENTS_FILE');
    if ($configuredPath !== false && trim($configuredPath) !== '') {
        return $configuredPath;
    }

    return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'poh-appointments.json';
}

function with_appointment_store(callable $operation, bool $write = false): mixed
{
    $path = appointment_store_path();
    $directory = dirname($path);

    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create appointment storage directory.');
    }

    $file = fopen($path, 'c+');
    if ($file === false) {
        throw new RuntimeException('Unable to open appointment storage.');
    }

    try {
        if (!flock($file, LOCK_EX)) {
            throw new RuntimeException('Unable to lock appointment storage.');
        }

        rewind($file);
        $contents = stream_get_contents($file);
        $appointments = $contents === ''
            ? []
            : json_decode($contents, true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($appointments)) {
            throw new RuntimeException('Appointment storage has an invalid format.');
        }

        $result = $operation($appointments);

        if ($write) {
            $encoded = json_encode($appointments, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            rewind($file);
            if (!ftruncate($file, 0) || fwrite($file, $encoded) === false || !fflush($file)) {
                throw new RuntimeException('Unable to save appointment storage.');
            }
        }

        return $result;
    } finally {
        flock($file, LOCK_UN);
        fclose($file);
    }
}

function appointment_store_all(): array
{
    return with_appointment_store(static function (array &$appointments): array {
        return $appointments;
    });
}

function appointment_store_create(array $appointment): array
{
    return with_appointment_store(static function (array &$appointments) use ($appointment): array {
        array_unshift($appointments, $appointment);
        return $appointment;
    }, true);
}

function appointment_store_update(string $id, string $status, string $receptionNote): bool
{
    return with_appointment_store(static function (array &$appointments) use ($id, $status, $receptionNote): bool {
        foreach ($appointments as &$appointment) {
            if (($appointment['id'] ?? '') !== $id) {
                continue;
            }

            $appointment['status'] = $status;
            $appointment['reception_note'] = $receptionNote;
            $appointment['updated_at'] = (new DateTimeImmutable())->format(DATE_ATOM);
            unset($appointment);
            return true;
        }

        unset($appointment);
        return false;
    }, true);
}