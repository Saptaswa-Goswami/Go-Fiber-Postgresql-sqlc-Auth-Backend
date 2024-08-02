-- name: CreateUser :one
INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3) RETURNING *;

-- name: GetUserByUsernameAndPassword :one
SELECT * FROM users WHERE username = $1 AND password = $2;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT *
FROM users
WHERE username = $1;
