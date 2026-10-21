}

# A manifest makes rollback specific to one execution instead of scanning arbitrary .bak files.
init_backup() {
  [[ -d "$STATE_DIR" ]] || install -d -m 0700 -- "$STATE_DIR" || return 1
  [[ ! -e "$STATE_DIR/$TIMESTAMP.manifest" ]] || return 1
  : > "$STATE_DIR/$TIMESTAMP.manifest"
  chmod 0600 "$STATE_DIR/$TIMESTAMP.manifest"
}

backup_target() {
  local file="$1" backup="${1}.bak-${TIMESTAMP}"
  assert_safe_target "$file" || return 1
  [[ -f "$file" && ! -e "$backup" && ! -L "$backup" ]] || return 1
  cp -p --no-dereference -- "$file" "$backup" || return 1
  printf '%s\n' "$backup" >> "$STATE_DIR/$TIMESTAMP.manifest"
}

# Update a config file atomically, retaining owner/mode via cp -p.
# Usage: replace_file path sed-expression (only literal known patterns are passed).
replace_file() {
  local file="$1" expr="$2" tmp
  if (( DRY_RUN )); then info "Would update: $file"; return 0; fi
  backup_target "$file" || { fail "Backup rejected: $file"; return 1; }
  tmp="$(mktemp "${file}.tmp.XXXXXXXX")" || { fail "Cannot create temp file: $file"; return 1; }
  if cp -p -- "$file" "$tmp" && sed -E "$expr" "$file" > "$tmp" && mv -f -- "$tmp" "$file"; then
    CHANGED=$((CHANGED+1))
    info "Updated: $file"
  else
    rm -f -- "$tmp"
    fail "Could not update: $file"
    return 1
  fi
}

php_bins() {
  local candidate
  for candidate in "$(command -v php 2>/dev/null || :)" /usr/bin/php[0-9]* \
      /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php \
      /opt/plesk/php/*/bin/php /www/server/php/*/bin/php \
      /opt/remi/php*/root/usr/bin/php /usr/local/php*/bin/php \
      /usr/local/lsws/lsphp*/bin/php; do
    [[ -n "$candidate" && -x "$candidate" && -f "$candidate" ]] && readlink -f -- "$candidate"
  done | sort -u
}

fpm_bins() {
  local candidate
  for candidate in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm \
      /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/alt/php*/usr/sbin/php-fpm \
      /opt/plesk/php/*/sbin/php-fpm /opt/remi/php*/root/usr/sbin/php-fpm \
      /www/server/php/*/sbin/php-fpm /usr/local/php*/sbin/php-fpm; do
    [[ -x "$candidate" && -f "$candidate" ]] && readlink -f -- "$candidate"
  done | sort -u
}

collect_php() {
  local binary version setting
  while IFS= read -r binary; do
    version="$("$binary" -r 'echo PHP_VERSION;' 2>/dev/null)" || continue
    setting="$("$binary" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)" || continue
    printf '%s\t%s\t%s\t%s\n' "$binary" 'cli' "$version" "$setting"
  done < <(php_bins)
  while IFS= read -r binary; do
    version="$("$binary" -v 2>/dev/null | awk 'NR==1 {print $2}')" || continue
    setting="$("$binary" -i 2>/dev/null | awk -F ' => ' '$1=="session.upload_progress.enabled" {print $2; exit}')" || continue
    [[ -n "$version" ]] && printf '%s\t%s\t%s\t%s\n' "$binary" 'fpm' "$version" "$setting"
  done < <(fpm_bins)
}

is_off() {
  case "${1,,}" in ''|0|off|false|no|none) return 0 ;; *) return 1 ;; esac
}

check_status() {
  local binary sapi version value count=0
  info 'Installed PHP binaries (CLI/FPM reported values may not reflect per-pool overrides):'
  while IFS=$'\t' read -r binary sapi version value; do
    [[ -n "$binary" ]] || continue
    count=$((count+1))
    if is_off "$value"; then
      info "$binary [$sapi $version]: upload_progress OFF"
    else
      warn "$binary [$sapi $version]: upload_progress ON/unknown ($value)"
      FAILED=$((FAILED+1))
    fi
  done < <(collect_php)
  (( count > 0 )) || warn 'No supported PHP binary found; discovery is incomplete'
  info 'Patch status is NOT inferred from PHP_VERSION: vendor backports and advisory data need independent verification.'
  (( FAILED == 0 && count > 0 ))
}

find_configs() {
  local root
  while IFS= read -r root; do
    find "$root" -xdev -type f \( -name 'php.ini' -o -name '*.ini' -o -name '*.conf' \) -print 2>/dev/null || :
  done < <(roots) | sort -u
}

# Applies conservative replacements to ini and FPM settings. Repeated directives are
# all rewritten so an earlier 'Off' cannot hide a later 'On'.
apply_mitigation() {
  local file basename content regex='^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*='
  local pool_re='^[[:space:]]*php_(admin_)?(flag|value)\[session[.]upload_progress[.]enabled\][[:space:]]*='
  local phpini_seen=0
  if (( !DRY_RUN )); then init_backup || die 'Cannot initialize protected backup manifest'; fi
  while IFS= read -r file; do
    basename="${file##*/}"
    case "$basename" in
      php.ini)
        phpini_seen=$((phpini_seen+1))
        if grep -Eiq "$regex" "$file"; then
          content="$(grep -Ei "$regex" "$file" || :)"
          if [[ -n "$content" ]] && ! printf '%s\n' "$content" | grep -Eivq '=[[:space:]]*(Off|0|false|no)[[:space:]]*(;.*)?$'; then
            SKIPPED=$((SKIPPED+1)); continue
          fi
          replace_file "$file" 's/^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=.*/session.upload_progress.enabled = Off/I' || :
        else
          if (( DRY_RUN )); then info "Would append setting to: $file"; continue; fi
          backup_target "$file" || { fail "Backup rejected: $file"; continue; }
          printf '\n; php2shell mitigation\nsession.upload_progress.enabled = Off\n' >> "$file" \
            && { CHANGED=$((CHANGED+1)); info "Updated: $file"; } || fail "Write failed: $file"
        fi
        ;;
      *.ini)
        if grep -Eiq "$regex" "$file" && grep -Ei "$regex" "$file" | grep -Eivq '=[[:space:]]*(Off|0|false|no)[[:space:]]*(;.*)?$'; then
          replace_file "$file" 's/^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=.*/session.upload_progress.enabled = Off/I' || :
        fi
        ;;
      *.conf)
        if grep -Eq "$pool_re" "$file"; then
          replace_file "$file" 's/^[[:space:]]*php_(admin_)?(flag|value)\[session[.]upload_progress[.]enabled\][[:space:]]*=.*/php_admin_flag[session.upload_progress.enabled] = off/' || :
        fi
        ;;
    esac
  done < <(find_configs)
  (( phpini_seen > 0 )) || warn 'No php.ini found in known paths'
  reload_services
  info "Changed=$CHANGED Skipped=$SKIPPED Errors=$FAILED"
  (( DRY_RUN || FAILED == 0 ))
}

reload_services() {
  (( DRY_RUN || NO_RESTART || CHANGED == 0 )) && return 0
  local svc
  if command -v systemctl >/dev/null 2>&1; then
    while IFS= read -r svc; do
      case "$svc" in
        apache2.service|httpd.service)
          if command -v apachectl >/dev/null 2>&1 && ! apachectl -t >/dev/null 2>&1; then
            fail "Apache configuration test failed; refusing reload: $svc"; continue
          fi ;;
      esac
      systemctl reload-or-restart "$svc" >/dev/null 2>&1 \
        && info "Reloaded: $svc" || fail "Service reload failed: $svc"
    done < <(systemctl list-units --type=service --no-legend --plain 2>/dev/null \
      | awk '{print $1}' \
      | grep -E '^(php.*fpm|ea-php.*|plesk-php.*|apache2|httpd|lsws|lshttpd|litespeed)[.]service$' || :)
  else
    warn 'No systemctl found; reload services manually'
  fi
}

revert() {
  local manifest stamp backup original
  if [[ -z "$REVERT_STAMP" ]]; then
    REVERT_STAMP="$(find "$STATE_DIR" -maxdepth 1 -type f -name '*.manifest' -printf '%f\n' 2>/dev/null \
      | sed -nE 's/^([0-9]{8}-[0-9]{6})[.]manifest$/\1/p' | sort | tail -1)"
  fi
  [[ -n "$REVERT_STAMP" ]] || die 'No recorded run found to revert'
  stamp="$REVERT_STAMP"; manifest="$STATE_DIR/$stamp.manifest"
  [[ -f "$manifest" && ! -L "$manifest" ]] || die "Missing run manifest: $manifest"
  while IFS= read -r backup; do
    [[ "$backup" == *.bak-"$stamp" ]] || { fail "Unexpected manifest entry: $backup"; continue; }
    original="${backup%.bak-$stamp}"
    [[ -f "$backup" && ! -L "$backup" ]] || { fail "Backup absent or symlink: $backup"; continue; }
    assert_safe_target "$original" || { fail "Unsafe restore destination: $original"; continue; }
    if (( DRY_RUN )); then info "Would restore: $original"; continue; fi
    cp -p -- "$backup" "$original" && { CHANGED=$((CHANGED+1)); info "Restored: $original"; } \
      || fail "Could not restore: $original"
  done < "$manifest"
  reload_services
  info "Restored=$CHANGED Errors=$FAILED"
  (( FAILED == 0 ))
}

print_waf_examples() {
  cat <<'EOF'
# Example only: do not deploy without adapting upload endpoints and testing.
# Blocking the upload-progress field in ModSecurity:
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
  "id:1026109,phase:2,deny,status:403,log,msg:'upload progress field blocked'"
