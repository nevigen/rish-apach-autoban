# Bash adapter for the Apache AutoBan configuration loader and validator.
load_config() {
    local data key value
    data=$(python3 "$BASE/config.py" load) || return 1
    while IFS='=' read -r key value; do
        printf -v "$key" '%s' "$value" || return 1
        export "$key"
    done <<< "$data"
}
setting() { python3 "$BASE/config.py" set "$1" "$2"; }
validate_setting() { python3 "$BASE/config.py" validate "$1" "$2"; }
