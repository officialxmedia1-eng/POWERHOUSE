<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/appointment_store.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['message' => 'Only POST requests are accepted.']);
    exit;
}

$name = trim((string) ($_POST['name'] ?? ''));
$email = trim((string) ($_POST['email'] ?? ''));
$phone = trim((string) ($_POST['phone'] ?? ''));
$service = trim((string) ($_POST['service'] ?? ''));
$preferredDate = trim((string) ($_POST['preferred_date'] ?? ''));
$patientNote = trim((string) ($_POST['patient_note'] ?? ''));
$allowedServices = ['ANC', 'Radiology', 'Lab Tests', 'Treatment', 'RNC', 'Other'];
$dateValue = $preferredDate === '' ? null : DateTimeImmutable::createFromFormat('!Y-m-d', $preferredDate);

if (
    $name === '' || mb_strlen($name) > 120 ||
    !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254 ||
    preg_match('/^[0-9+().\-\s]{7,30}$/D', $phone) !== 1 ||
    !in_array($service, $allowedServices, true) ||
    ($preferredDate !== '' && ($dateValue === false || $dateValue->format('Y-m-d') !== $preferredDate)) ||
    mb_strlen($patientNote) > 1000
) {
    http_response_code(422);
    echo json_encode(['message' => 'Please provide valid contact details and select a service.']);
    exit;
}

try {
    $appointment = appointment_store_create([
        'id' => bin2hex(random_bytes(12)),
        'name' => $name,
        'email' => $email,
        'phone' => $phone,
        'service' => $service,
        'preferred_date' => $preferredDate,
        'patient_note' => $patientNote,
        'status' => 'new',
        'reception_note' => '',
        'created_at' => (new DateTimeImmutable())->format(DATE_ATOM),
        'updated_at' => null,
    ]);
} catch (Throwable $error) {
    error_log('Could not save appointment request: ' . $error->getMessage());
    http_response_code(500);
    echo json_encode(['message' => 'We could not save your request. Please call the hospital.']);
    exit;
}

$recipient = getenv('APPOINTMENT_EMAIL');
if ($recipient && filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
    $subject = 'New appointment request';
    $message = "Name: {$appointment['name']}\nEmail: {$appointment['email']}\nPhone: {$appointment['phone']}\nService: {$appointment['service']}\nPreferred date: {$appointment['preferred_date']}\nNotes: {$appointment['patient_note']}\n";
    $headers = "From: website@" . ($_SERVER['SERVER_NAME'] ?? 'localhost') . "\r\n";
    $headers .= "Reply-To: {$appointment['email']}\r\n";

    if (!mail($recipient, $subject, $message, $headers)) {
        error_log('Appointment request saved, but email notification failed.');
    }
}

http_response_code(201);
echo json_encode(['message' => 'Thanks. Your request has been received by our reception team.']);