# php2shell — CVE-2026-109618 / CVE-2026-109619

> **Critical Advisory (CVSS v4.0: 9.2 — Critical):** On October 20, details of two pre-authentication remote code execution vulnerabilities in the PHP core were leaked online ahead of coordinated disclosure. Successful exploitation can allow arbitrary command execution on the web server.

***

## Table of Contents

- [Overview](#overview)
  - [Technical Cause](#technical-cause)
  - [Verification and Target Environments](#verification-and-target-environments)
- [Affected PHP Versions](#affected-php-versions)
- [Threat Landscape and Detection](#threat-landscape-and-detection)
  - [Behavioral Indicators and Suspicious Child Processes](#behavioral-indicators-and-suspicious-child-processes)
  - [Monitoring Recommendation](#monitoring-recommendation)
- [Action Items for Organizations](#action-items-for-organizations)
- [Proof of Concept (PoC)](#proof-of-concept-poc)
- [Mitigation and Source Patching](#mitigation-and-source-patching)
  - [1. Configuration Mitigation as an Immediate Measure](#1-configuration-mitigation-as-an-immediate-measure)
  - [2. Automated Quick Fix](#2-automated-quick-fix)
  - [3. Source Code Change: `session-upload-progress-counters.patch`](#3-source-code-change-session-upload-progress-counterspatch)
  - [4. Custom Cloudflare WAF Rules](#4-custom-cloudflare-waf-rules)
  - [5. FrankenPHP Caddyfile Configuration](#5-frankenphp-caddyfile-configuration)
  - [6. Lighttpd Configuration](#6-lighttpd-configuration)
  - [7. Apache Mitigation with ModSecurity and .htaccess](#7-apache-mitigation-with-modsecurity-and-htaccess)
- [Disclaimer](#disclaimer)

***

## Overview

`php2shell` is the collective name for two severe vulnerabilities in the PHP core: **CVE-2026-109618** and **CVE-2026-109619**. The demonstrated attack chain abuses a heap use-after-free condition in PHP’s session upload progress functionality and can ultimately lead to arbitrary code execution through `zend_call_function` and `system()`.

- **Severity:** Critical, with a CVSS v4.0 score of 9.2.
- **Potentially affected versions:** Reports indicate that PHP 5, 6, 7, and 8 may be affected. Official fixes are primarily expected for supported PHP 8 branches, leaving end-of-life releases without an official vendor patch.
- **Industry tracking:** Security researchers have confirmed the vulnerabilities. watchTowr reproduced CVE-2026-109618, while Huntress and Florian Roth are tracking related activity, including through process-watcher.

### Technical Cause

PHP’s upload progress handler, `php_session_rfc1867_callback` in `ext/session/session.c`, stores two raw `zval *` bucket pointers — `post_bytes_processed` and `current_file_bytes_processed` — directly within live `HashTable` structures.

During request processing, the issue unfolds as follows:

1. **Trigger:** A regular multipart `POST` request activates progress tracking when `session.upload_progress.enabled = 1` is configured.
2. **Free:** During a progress update, PHP re-reads session data. `zend_hash_update()` destroys the existing data structure using `zval_ptr_dtor`, releasing the associated memory block.
3. **Reuse:** The freed bucket memory can subsequently be reallocated. The remaining dangling pointer may then reference forged `zend_fcall_info` and `zend_internal_function` structures.
4. **Execution:** PHP subsequently calls `zend_call_function()`, which can result in the execution of arbitrary system commands.

### Verification and Target Environments

- The vulnerability has been confirmed on standard `php-src` builds, including PHP 8.4.4 and 8.2.34.
- Symbol offsets between `zval_ptr_dtor` and `zend_call_function` can be used to account for differences in binary layouts across distributions, such as Debian Bookworm, Ubuntu Noble, and Ubuntu Jammy.

***

## Affected PHP Versions

| PHP Branch | Status | Affected Versions | Fixed / Secure Version | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **PHP 8.5** | Actively supported | < 8.5.12 | **8.5.12** | Emergency security release available |
| **PHP 8.4** | Actively supported | < 8.4.27 | **8.4.27** | Emergency security release available |
| **PHP 8.3** | Actively supported | < 8.3.36 | **8.3.36** | Emergency security release available |
| **PHP 8.2** | Security-only support | < 8.2.35 | **8.2.35** | Emergency security release available |
| **PHP 8.1** | End of Life | All 8.1.x versions | No official patch | Set `session.upload_progress.enabled = Off` or use ELS/distribution backports |
| **PHP 8.0** | End of Life | All 8.0.x versions | No official patch | Official support has ended; configuration mitigation is required |
| **PHP 7.x** | End of Life | PHP 7.0 through 7.4 | No official patch | The `ext/session` logic is vulnerable; urgent mitigation or upgrade required |
| **PHP 5.x** | End of Life | 5.4.0 and later, with RFC1867 progress tracking | No official patch | Official support has ended; isolate the host or disable upload progress |

> [!WARNING]
> PHP 8.1 and older end-of-life versions no longer receive official security patches from the PHP Foundation. For these environments, immediately set `session.upload_progress.enabled = Off`, or rebuild PHP using the provided C source patch.

***

## Threat Landscape and Detection

Successful exploitation of `php2shell` commonly results in unusual child processes being launched directly by PHP worker processes, such as `php-fpm`, `php-cgi`, `php-cgi.exe`, `httpd`, or `apache2`.

### Behavioral Indicators and Suspicious Child Processes

Monitor and alert when a PHP worker process launches any of the following:

- **Interactive shells:** `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell.exe`
- **Script interpreters:** `python`, `perl`
- **Network and transfer utilities:** `curl`, `wget`, `nc`, `certutil.exe`
- **Common reverse-shell patterns:** `/dev/tcp/`, `fsockopen`, `mkfifo`
- **Immediate reconnaissance commands:** `whoami`, `id`, `uname -a`, `ipconfig`



## Action Items for Organizations

1. **Inventory all PHP environments.**
   - Internet-facing web servers running applications such as WordPress, Drupal, Joomla, or Magento.
   - Internal appliances, hosting panels such as cPanel and Plesk, and standalone binaries such as `php.exe` and `php-cgi.exe`.

2. **Prepare patch windows in advance.**
   - Official emergency patches from PHP and downstream Linux distributions are expected around **Wednesday, October 21 at 14:00 UTC (10:00 AM ET)**.
   - Apply vendor updates as soon as they become available.

3. **Isolate end-of-life installations.**
   - Environments running PHP 5.x, 7.x, 8.0, or 8.1 may not receive official upstream backports.
   - Restrict access through a VPN, apply strict WAF rules, or remove direct internet exposure.

4. **Initiate incident response when suspicious activity is identified.**
   - Isolate the host if suspicious child processes or unexpected files are observed.
   - Preserve web server and PHP logs for forensic review.
   - Inspect web roots and temporary directories such as `/tmp` and `/var/tmp` for deployed webshells or transient execution artifacts.

***

## Proof of Concept (PoC)

This repository is dedicated to security research and the development of a Proof of Concept for **php2shell (CVE-2026-109618 / CVE-2026-109619)**.

***

## Mitigation and Source Patching

Until official vendor packages are updated in your repositories, environments can be protected through configuration changes, automation, or by rebuilding PHP with the included source patch.

### 1. Configuration Mitigation as an Immediate Measure

The vulnerability depends on PHP’s session upload progress mechanism. This setting is enabled by default. Disabling the directive neutralizes the attack vector while preserving normal file upload functionality.

In `php.ini`:

```ini
session.upload_progress.enabled = Off
```

Or in a PHP-FPM pool configuration, for example `/etc/php/*/fpm/pool.d/www.conf`:

```ini
php_admin_flag[session.upload_progress.enabled] = off
```

Afterward, reload or restart the affected services, for example using `systemctl reload php-fpm` or `systemctl reload apache2`.

### 2. Automated Quick Fix

A mitigation helper script is available in the [`quick-fix/`](quick-fix/) directory.

- **Check the current status:**

  ```bash
  sudo ./quick-fix/run.sh --check
  ```

- **Test the mitigation without making changes:**

  ```bash
  sudo ./quick-fix/run.sh --dry-run
  ```

- **Apply the mitigation:**

  ```bash
  sudo ./quick-fix/run.sh
  ```

- **Revert the changes:**

  ```bash
  sudo ./quick-fix/run.sh --revert
  ```

### 3. Source Code Change: `session-upload-progress-counters.patch`

For environments that build PHP from source or maintain custom distribution packages, a C-level source patch is available: [`patch/session-upload-progress-counters.patch`](patch/session-upload-progress-counters.patch).

**What the patch fixes:**

The change addresses the underlying cause in `ext/session/session.c` and `ext/session/php_session.h`. Instead of retaining vulnerable raw `zval *` bucket pointers — `post_bytes_processed` and `current_file_bytes_processed` — within dynamic `HashTable` structures, the patch:

- Stores counters as direct `zend_long` values.
- Introduces `php_session_rfc1867_sync_counters()` to safely resolve and update array entries without leaving dangling references.

**How to apply the patch:**

1. Navigate to the root of your `php-src` source directory:

   ```bash
   cd /path/to/php-src
   ```

2. Test the patch first:

   ```bash
   # When building from a git clone
   git apply --check /path/to/patch/session-upload-progress-counters.patch

   # Or using GNU patch
   patch -p1 --dry-run < /path/to/patch/session-upload-progress-counters.patch
   ```

3. Apply the patch:

   ```bash
   # When building from a git clone
   git apply /path/to/patch/session-upload-progress-counters.patch

   # Or using GNU patch
   patch -p1 < /path/to/patch/session-upload-progress-counters.patch
   ```

4. Recompile and install PHP:

   ```bash
   ./buildconf --force   # if needed
   ./configure <your-options>
   make -j"$(nproc)"
   sudo make install
   ```

5. Restart the PHP runtime or web services:

   ```bash
   sudo systemctl restart php-fpm
   # or
   sudo systemctl restart apache2
   ```

### 4. Custom Cloudflare WAF Rules

Recommended Cloudflare WAF rule templates are available in the [`cloudflare-rule-fix/`](cloudflare-rule-fix/) directory:

- Comprehensive multipart request blocking, with exceptions for legitimate upload routes.
- Request body inspection for `PHP_SESSION_UPLOAD_PROGRESS`, available on Enterprise plans.

> Blocking requests solely based on the `PHPSESSID` cookie is strongly discouraged because it breaks valid user sessions. See [cloudflare-rule-fix/README.md](cloudflare-rule-fix/README.md) for the full rule syntax and details.

### 5. FrankenPHP Caddyfile Configuration

To disable session upload progress globally in FrankenPHP environments, add the contents of [`frankenphp/Caddyfile-snippet`](frankenphp/Caddyfile-snippet) to your global Caddyfile block:

```caddyfile
{
    frankenphp {
        php_ini session.upload_progress.enabled 0
    }
}
```

### 6. Lighttpd Configuration

In Lighttpd environments, multipart requests using `POST`, `PUT`, or `PATCH` can be blocked on virtual hosts or directories that do not require file uploads. Use [`lighttpd/php2shell.conf`](lighttpd/php2shell.conf):

```lighttpd
$HTTP["request-method"] =~ "^(POST|PUT|PATCH)$" {
    $REQUEST_HEADER["Content-Type"] =~ "(?i)^\s*multipart/form-data([;,[:space:]]|$)" {
        url.access-deny = ( "" )
    }
}
```

### 7. Apache Mitigation with ModSecurity and .htaccess

Two mitigation options are available for Apache environments.

**ModSecurity rule:** block requests containing the `PHP_SESSION_UPLOAD_PROGRESS` parameter using [`apache/modsecurity-php2shell.conf`](apache/modsecurity-php2shell.conf):

```apache
SecRequestBodyAccess On
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1026109618,phase:2,t:none,deny,status:403,log,\
    msg:'php2shell: PHP_SESSION_UPLOAD_PROGRESS field blocked (CVE-2026-109618/109619)'"
```

**`.htaccess` / mod_rewrite rule:** block multipart requests before they reach the PHP interpreter in directories that do not require file uploads. Use [`apache/.htaccess`](apache/.htaccess):

```apache
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(POST|PUT|PATCH)$ [NC]
RewriteCond %{HTTP:Content-Type} ^[[:space:]]*multipart/form-data([;,[:space:]]|$) [NC]
RewriteRule ^ - [F,L]
```

***

## Disclaimer

This project is intended strictly for educational purposes and authorized security research. Use it only in environments that you own or for which you have explicit permission to test.