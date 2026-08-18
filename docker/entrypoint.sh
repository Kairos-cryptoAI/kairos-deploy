#!/bin/sh
set -eu

# Bind comma-separated ENV_NAME=/run/secrets/file pairs without printing values.
if [ -n "${KAIROS_SECRET_BINDINGS:-}" ]; then
    old_ifs=$IFS
    IFS=','
    for binding in ${KAIROS_SECRET_BINDINGS}; do
        name=${binding%%=*}
        path=${binding#*=}
        case "$name" in
            [A-Z_][A-Z0-9_]*) ;;
            *) echo "invalid secret environment name" >&2; exit 78 ;;
        esac
        if [ "$path" = "$binding" ] || [ ! -r "$path" ]; then
            echo "required secret file is not readable for $name" >&2
            exit 78
        fi
        value=$(cat "$path")
        if [ -z "$value" ]; then
            echo "required secret file is empty for $name" >&2
            exit 78
        fi
        export "$name=$value"
        unset value
    done
    IFS=$old_ifs
    unset KAIROS_SECRET_BINDINGS
fi

exec "$@"
