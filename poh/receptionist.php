<?php
declare(strict_types=1);

require_once __DIR__ . '/appointment_store.php';
require_once __DIR__ . '/receptionist_credentials.php';

ini_set('session.use_strict_mode', '1');
session_name('poh_reception');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();
header('Cache-Control: no-store, private');

function receptionist_escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function receptionist_redirect(): never
{
    header('Location: receptionist.php', true, 303);
    exit;
}

function receptionist_date(string $value): string
{
    $timestamp = strtotime($value);
    return $timestamp === false ? 'Unknown' : date('M j, Y g:i a', $timestamp);
}

$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));
$csrfToken = (string) $_SESSION['csrf_token'];
$loginError = '';
$loginNotice = (string) ($_SESSION['reception_login_notice'] ?? '');
unset($_SESSION['reception_login_notice']);
$flash = (string) ($_SESSION['reception_flash'] ?? '');
unset($_SESSION['reception_flash']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');
    $submittedToken = (string) ($_POST['csrf_token'] ?? '');

    if (!hash_equals($csrfToken, $submittedToken)) {
        http_response_code(400);
        $loginError = 'Your session expired. Reload the page and try again.';
    } elseif ($action === 'request_password_reset' && empty($_SESSION['receptionist_authenticated'])) {
      $submittedEmail = strtolower(trim((string) ($_POST['email'] ?? '')));
      $recoveryEmail = strtolower(trim((string) (getenv('RECEPTIONIST_EMAIL') ?: '')));
      $resetUrl = trim((string) (getenv('RECEPTIONIST_RESET_URL') ?: ''));
      $resetToken = null;

      try {
        if (
          $recoveryEmail !== '' &&
          filter_var($recoveryEmail, FILTER_VALIDATE_EMAIL) &&
          $submittedEmail === $recoveryEmail &&
          filter_var($resetUrl, FILTER_VALIDATE_URL) &&
          in_array(strtolower((string) parse_url($resetUrl, PHP_URL_SCHEME)), ['http', 'https'], true)
        ) {
          $resetToken = receptionist_create_reset_token();
          if ($resetToken !== null) {
            $separator = str_contains($resetUrl, '?') ? '&' : '?';
            $resetLink = $resetUrl . $separator . 'token=' . rawurlencode($resetToken);
            $subject = 'Reception desk password reset';
            $message = "A request was made to reset the receptionist password.\n\nOpen this one-use link within 30 minutes:\n{$resetLink}\n\nIf you did not request this, you can ignore this message.";
            $headers = "From: {$recoveryEmail}\r\n";

            if (!mail($recoveryEmail, $subject, $message, $headers)) {
              receptionist_clear_reset_token();
              error_log('Could not send receptionist password reset email.');
            }
          }
        }
      } catch (Throwable $error) {
        if ($resetToken !== null) {
          try {
            receptionist_clear_reset_token();
          } catch (Throwable $clearError) {
            error_log('Could not clear an unsent receptionist reset token.');
          }
        }
        error_log('Could not process receptionist password reset request: ' . $error->getMessage());
      }

      $_SESSION['reception_login_notice'] = 'If the details match and email recovery is configured, reset instructions will be sent shortly.';
      receptionist_redirect();
    } elseif ($action === 'reset_password' && empty($_SESSION['receptionist_authenticated'])) {
      $resetToken = (string) ($_POST['token'] ?? '');
      $newPassword = (string) ($_POST['new_password'] ?? '');
      $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

      try {
        if (mb_strlen($newPassword) < 12 || mb_strlen($newPassword) > 72 || strlen($newPassword) > 72) {
          $loginError = 'Choose a password between 12 and 72 characters.';
        } elseif (!hash_equals($newPassword, $confirmPassword)) {
          $loginError = 'The new password entries did not match.';
        } elseif (receptionist_consume_reset_token($resetToken, $newPassword)) {
          session_regenerate_id(true);
          $_SESSION['receptionist_authenticated'] = false;
          $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
          $_SESSION['reception_login_notice'] = 'Password reset. Sign in with your new password.';
          receptionist_redirect();
        } else {
          $loginError = 'This reset link is invalid or expired. Request another link.';
        }
      } catch (Throwable $error) {
        error_log('Could not reset receptionist password: ' . $error->getMessage());
        $loginError = 'We could not reset the password. Request a new link and try again.';
      }
    } elseif ($action === 'login' && empty($_SESSION['receptionist_authenticated'])) {
        $lockedUntil = (int) ($_SESSION['login_locked_until'] ?? 0);
      $passwordMatches = false;
      $credentialError = false;

      try {
        $passwordMatches = receptionist_password_matches((string) ($_POST['password'] ?? ''));
      } catch (Throwable $error) {
        error_log('Could not verify receptionist credentials: ' . $error->getMessage());
        $credentialError = true;
      }

      if (!receptionist_password_is_configured()) {
            $loginError = 'Receptionist access has not been configured on the server.';
      } elseif ($credentialError) {
        $loginError = 'Receptionist sign-in is temporarily unavailable. Please contact the site administrator.';
        } elseif ($lockedUntil > time()) {
            $loginError = 'Too many attempts. Please wait a few minutes and try again.';
      } elseif ($passwordMatches) {
            session_regenerate_id(true);
            $_SESSION['receptionist_authenticated'] = true;
            $_SESSION['login_attempts'] = 0;
            $_SESSION['login_locked_until'] = 0;
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['reception_flash'] = 'Signed in to the reception desk.';
            receptionist_redirect();
        } else {
            $_SESSION['login_attempts'] = (int) ($_SESSION['login_attempts'] ?? 0) + 1;
            if ($_SESSION['login_attempts'] >= 5) {
                $_SESSION['login_attempts'] = 0;
                $_SESSION['login_locked_until'] = time() + 300;
            }
            $loginError = 'The password was not recognized.';
        }
    } elseif ($action === 'logout' && !empty($_SESSION['receptionist_authenticated'])) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            setcookie(session_name(), '', [
                'expires' => time() - 42000,
                'path' => '/',
                'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
        }
        session_destroy();
        receptionist_redirect();
    } elseif ($action === 'change_password' && !empty($_SESSION['receptionist_authenticated'])) {
      $currentPassword = (string) ($_POST['current_password'] ?? '');
      $newPassword = (string) ($_POST['new_password'] ?? '');
      $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

      try {
        if (!receptionist_password_matches($currentPassword)) {
          $_SESSION['reception_flash'] = 'The current password was not recognized.';
        } elseif (mb_strlen($newPassword) < 12 || mb_strlen($newPassword) > 72 || strlen($newPassword) > 72) {
          $_SESSION['reception_flash'] = 'Choose a password between 12 and 72 characters.';
        } elseif (!hash_equals($newPassword, $confirmPassword)) {
          $_SESSION['reception_flash'] = 'The new password entries did not match.';
        } elseif (hash_equals($currentPassword, $newPassword)) {
          $_SESSION['reception_flash'] = 'Choose a password different from your current one.';
        } else {
          receptionist_save_password($newPassword);
          session_regenerate_id(true);
          $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
          $_SESSION['reception_flash'] = 'Password changed. Use your new password next time you sign in.';
        }
      } catch (Throwable $error) {
        error_log('Could not change receptionist password: ' . $error->getMessage());
        $_SESSION['reception_flash'] = 'We could not save the new password. Please try again.';
      }

      receptionist_redirect();
    } elseif ($action === 'update' && !empty($_SESSION['receptionist_authenticated'])) {
        $statuses = ['new', 'contacted', 'confirmed', 'cancelled'];
        $id = trim((string) ($_POST['id'] ?? ''));
        $status = (string) ($_POST['status'] ?? '');
        $receptionNote = trim((string) ($_POST['reception_note'] ?? ''));

        if ($id === '' || !in_array($status, $statuses, true) || mb_strlen($receptionNote) > 1000) {
            $_SESSION['reception_flash'] = 'Please check the status and keep notes under 1,000 characters.';
        } else {
            try {
                $_SESSION['reception_flash'] = appointment_store_update($id, $status, $receptionNote)
                    ? 'Appointment updated.'
                    : 'That appointment could not be found.';
            } catch (Throwable $error) {
                error_log('Could not update appointment: ' . $error->getMessage());
                $_SESSION['reception_flash'] = 'We could not save that update. Please try again.';
            }
        }

        receptionist_redirect();
    }
}

$isAuthenticated = !empty($_SESSION['receptionist_authenticated']);
$resetToken = trim((string) ($_GET['token'] ?? ''));
$resetTokenValid = false;
if (!$isAuthenticated && $resetToken !== '') {
  try {
    $resetTokenValid = receptionist_reset_token_is_valid($resetToken);
  } catch (Throwable $error) {
    error_log('Could not verify receptionist reset link: ' . $error->getMessage());
  }
}
$allAppointments = [];
$storageError = '';
$filteredAppointments = [];
$statusLabels = [
    'new' => 'New',
    'contacted' => 'Contacted',
    'confirmed' => 'Confirmed',
    'cancelled' => 'Cancelled',
];
$services = ['ANC', 'Radiology', 'Lab Tests', 'Treatment', 'RNC', 'Other'];
$statusFilter = '';
$serviceFilter = '';
$search = '';
$sort = 'newest';

if ($isAuthenticated) {
    try {
        $allAppointments = appointment_store_all();
    } catch (Throwable $error) {
        error_log('Could not read appointments: ' . $error->getMessage());
        $storageError = 'Appointment records are temporarily unavailable.';
    }

    $statusFilter = (string) ($_GET['status'] ?? '');
    $serviceFilter = (string) ($_GET['service'] ?? '');
    $search = trim((string) ($_GET['q'] ?? ''));
    $sort = (string) ($_GET['sort'] ?? 'newest');

    if (!array_key_exists($statusFilter, $statusLabels)) {
        $statusFilter = '';
    }
    if (!in_array($serviceFilter, $services, true)) {
        $serviceFilter = '';
    }
    if (!in_array($sort, ['newest', 'oldest'], true)) {
        $sort = 'newest';
    }
    $search = mb_substr($search, 0, 100);

    $filteredAppointments = array_values(array_filter($allAppointments, static function (array $appointment) use ($statusFilter, $serviceFilter, $search): bool {
        if ($statusFilter !== '' && ($appointment['status'] ?? '') !== $statusFilter) {
            return false;
        }
        if ($serviceFilter !== '' && ($appointment['service'] ?? '') !== $serviceFilter) {
            return false;
        }
        if ($search !== '') {
            $searchable = implode(' ', [
                (string) ($appointment['name'] ?? ''),
                (string) ($appointment['email'] ?? ''),
                (string) ($appointment['phone'] ?? ''),
                (string) ($appointment['service'] ?? ''),
            ]);
            if (mb_stripos($searchable, $search) === false) {
                return false;
            }
        }
        return true;
    }));

    usort($filteredAppointments, static function (array $first, array $second) use ($sort): int {
        $firstTime = strtotime((string) ($first['created_at'] ?? '')) ?: 0;
        $secondTime = strtotime((string) ($second['created_at'] ?? '')) ?: 0;
        return $sort === 'oldest' ? $firstTime <=> $secondTime : $secondTime <=> $firstTime;
    });
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Reception desk</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Newsreader:opsz,wght@6..72,500;6..72,600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="receptionist.css">
</head>
<body class="desk-page">
  <header class="desk-nav">
    <div class="desk-brand">Reception desk</div>
    <div class="desk-nav-actions">
      <?php if ($isAuthenticated): ?>
        <form method="post" class="logout-form">
          <input type="hidden" name="action" value="logout">
          <input type="hidden" name="csrf_token" value="<?= receptionist_escape($csrfToken) ?>">
          <button class="quiet-button" type="submit">Sign out</button>
        </form>
      <?php endif; ?>
    </div>
  </header>

  <?php if (!$isAuthenticated): ?>
    <main class="login-wrap">
      <section class="login-panel">
        <p class="eyebrow">Staff access</p>
        <?php if ($resetToken !== ''): ?>
          <h1>Reset password</h1>
          <p>Choose a new password for receptionist sign-in.</p>
          <?php if ($loginError !== ''): ?><p class="desk-alert" role="alert"><?= receptionist_escape($loginError) ?></p><?php endif; ?>
          <?php if ($resetTokenValid): ?>
            <form method="post" class="login-form">
              <input type="hidden" name="action" value="reset_password">
              <input type="hidden" name="csrf_token" value="<?= receptionist_escape($csrfToken) ?>">
              <input type="hidden" name="token" value="<?= receptionist_escape($resetToken) ?>">
              <label for="new-password">New password</label>
              <input id="new-password" name="new_password" type="password" autocomplete="new-password" minlength="12" maxlength="72" required>
              <label for="confirm-password">Confirm new password</label>
              <input id="confirm-password" name="confirm_password" type="password" autocomplete="new-password" minlength="12" maxlength="72" required>
              <p class="password-guidance">Use 12 to 72 characters.</p>
              <button class="desk-primary" type="submit">Reset password</button>
            </form>
          <?php else: ?>
            <p class="desk-alert" role="alert">This reset link is invalid or expired. Request another link below.</p>
            <a class="recovery-link" href="receptionist.php#forgot-password">Request a new reset link</a>
          <?php endif; ?>
        <?php else: ?>
          <h1>Reception desk</h1>
          <p>Sign in to review and organize appointment requests.</p>
          <?php if ($loginNotice !== ''): ?><p class="desk-flash" role="status"><?= receptionist_escape($loginNotice) ?></p><?php endif; ?>
        <?php if ($loginError !== ''): ?><p class="desk-alert" role="alert"><?= receptionist_escape($loginError) ?></p><?php endif; ?>
        <?php if (!receptionist_password_is_configured()): ?>
          <p class="setup-alert">Set the <code>RECEPTIONIST_PASSWORD</code> environment variable for Apache before signing in.</p>
        <?php else: ?>
          <form method="post" class="login-form">
            <input type="hidden" name="action" value="login">
            <input type="hidden" name="csrf_token" value="<?= receptionist_escape($csrfToken) ?>">
            <label for="password">Receptionist password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>
            <button class="desk-primary" type="submit">Sign in</button>
          </form>
        <?php endif; ?>
          <details class="forgot-password" id="forgot-password">
            <summary>Forgot password?</summary>
            <p>Enter the recovery email configured for the reception desk. If it matches, we’ll send a one-use reset link.</p>
            <form method="post" class="recovery-form">
              <input type="hidden" name="action" value="request_password_reset">
              <input type="hidden" name="csrf_token" value="<?= receptionist_escape($csrfToken) ?>">
              <label for="recovery-email">Recovery email</label>
              <input id="recovery-email" name="email" type="email" autocomplete="email" maxlength="254" required>
              <button class="desk-primary" type="submit">Send reset link</button>
            </form>
          </details>
        <?php endif; ?>
      </section>
    </main>
  <?php else: ?>
    <main class="desk-shell">
      <div class="desk-heading">
        <div>
          <p class="eyebrow">Reception</p>
          <h1>Appointment requests</h1>
          <p>Review patient details, follow up, and update each request's status.</p>
        </div>
        <p class="desk-date"><?= receptionist_escape(date('l, F j, Y')) ?></p>
      </div>

      <?php if ($flash !== ''): ?><p class="desk-flash" role="status"><?= receptionist_escape($flash) ?></p><?php endif; ?>
      <?php if ($storageError !== ''): ?><p class="desk-alert" role="alert"><?= receptionist_escape($storageError) ?></p><?php endif; ?>

      <section class="desk-stats" aria-label="Appointment totals">
        <div><span>All requests</span><strong><?= count($allAppointments) ?></strong></div>
        <div><span>New to review</span><strong><?= count(array_filter($allAppointments, static fn (array $item): bool => ($item['status'] ?? 'new') === 'new')) ?></strong></div>
        <div><span>Confirmed</span><strong><?= count(array_filter($allAppointments, static fn (array $item): bool => ($item['status'] ?? '') === 'confirmed')) ?></strong></div>
      </section>

      <form class="desk-filters" method="get" action="receptionist.php">
        <label class="search-field"><span>Search</span><input type="search" name="q" value="<?= receptionist_escape($search) ?>" placeholder="Name, phone, email"></label>
        <label><span>Status</span><select name="status"><option value="">All statuses</option><?php foreach ($statusLabels as $value => $label): ?><option value="<?= receptionist_escape($value) ?>" <?= $statusFilter === $value ? 'selected' : '' ?>><?= receptionist_escape($label) ?></option><?php endforeach; ?></select></label>
        <label><span>Service</span><select name="service"><option value="">All services</option><?php foreach ($services as $service): ?><option value="<?= receptionist_escape($service) ?>" <?= $serviceFilter === $service ? 'selected' : '' ?>><?= receptionist_escape($service) ?></option><?php endforeach; ?></select></label>
        <label><span>Sort by</span><select name="sort"><option value="newest" <?= $sort === 'newest' ? 'selected' : '' ?>>Newest first</option><option value="oldest" <?= $sort === 'oldest' ? 'selected' : '' ?>>Oldest first</option></select></label>
        <button class="desk-filter-button" type="submit">Apply filters</button>
      </form>

      <div class="request-count"><?= count($filteredAppointments) ?> request<?= count($filteredAppointments) === 1 ? '' : 's' ?></div>
      <?php if ($filteredAppointments === []): ?>
        <section class="desk-empty"><h2>No requests found</h2><p>New patient appointment requests will appear here.</p></section>
      <?php else: ?>
        <section class="request-list" aria-label="Appointment requests">
          <?php foreach ($filteredAppointments as $appointment): ?>
            <?php
              $appointmentStatus = (string) ($appointment['status'] ?? 'new');
              if (!isset($statusLabels[$appointmentStatus])) {
                  $appointmentStatus = 'new';
              }
              $appointmentId = (string) ($appointment['id'] ?? '');
              $patientName = (string) ($appointment['name'] ?? 'Unknown patient');
            ?>
            <article class="request-row">
              <div class="request-main">
                <div class="request-title-line">
                  <h2><?= receptionist_escape($patientName) ?></h2>
                  <span class="status-pill status-<?= receptionist_escape($appointmentStatus) ?>"><?= receptionist_escape($statusLabels[$appointmentStatus]) ?></span>
                </div>
                <p class="request-service"><?= receptionist_escape((string) ($appointment['service'] ?? 'Other')) ?><?php if (!empty($appointment['preferred_date'])): ?> <span>· Preferred <?= receptionist_escape((string) $appointment['preferred_date']) ?></span><?php endif; ?></p>
                <p class="request-submitted">Received <?= receptionist_escape(receptionist_date((string) ($appointment['created_at'] ?? ''))) ?></p>
                <div class="request-contact">
                  <a href="tel:<?= receptionist_escape((string) ($appointment['phone'] ?? '')) ?>"><?= receptionist_escape((string) ($appointment['phone'] ?? 'No phone supplied')) ?></a>
                  <a href="mailto:<?= receptionist_escape((string) ($appointment['email'] ?? '')) ?>"><?= receptionist_escape((string) ($appointment['email'] ?? 'No email supplied')) ?></a>
                </div>
                <?php if (!empty($appointment['patient_note'])): ?><p class="patient-message"><strong>Patient note</strong><?= nl2br(receptionist_escape((string) $appointment['patient_note'])) ?></p><?php endif; ?>
              </div>
              <form method="post" class="request-update">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="csrf_token" value="<?= receptionist_escape($csrfToken) ?>">
                <input type="hidden" name="id" value="<?= receptionist_escape($appointmentId) ?>">
                <label><span>Status</span><select name="status"><?php foreach ($statusLabels as $value => $label): ?><option value="<?= receptionist_escape($value) ?>" <?= $appointmentStatus === $value ? 'selected' : '' ?>><?= receptionist_escape($label) ?></option><?php endforeach; ?></select></label>
                <label><span>Reception notes (private)</span><textarea name="reception_note" rows="2" maxlength="1000" placeholder="Add a follow-up note"><?= receptionist_escape((string) ($appointment['reception_note'] ?? '')) ?></textarea></label>
                <button class="desk-primary" type="submit">Save update</button>
              </form>
            </article>
          <?php endforeach; ?>
        </section>
      <?php endif; ?>
    </main>
    <footer class="desk-footer">
      <div class="desk-footer-inner">
        <details class="password-settings">
          <summary>Change password</summary>
          <form method="post" class="password-change-form">
            <input type="hidden" name="action" value="change_password">
            <input type="hidden" name="csrf_token" value="<?= receptionist_escape($csrfToken) ?>">
            <label><span>Current password</span><input name="current_password" type="password" autocomplete="current-password" required></label>
            <label><span>New password</span><input name="new_password" type="password" autocomplete="new-password" minlength="12" maxlength="72" required></label>
            <label><span>Confirm new password</span><input name="confirm_password" type="password" autocomplete="new-password" minlength="12" maxlength="72" required></label>
            <p class="password-guidance">Use 12 to 72 characters. Your new password is stored as a hash outside the public website folder.</p>
            <button class="desk-primary" type="submit">Update password</button>
          </form>
        </details>
      </div>
    </footer>
  <?php endif; ?>
</body>
</html>