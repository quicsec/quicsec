package httpapi.authz

default allow = false  # Permitir por padrão


allow {
    not contains(input.path, "/admin")
}