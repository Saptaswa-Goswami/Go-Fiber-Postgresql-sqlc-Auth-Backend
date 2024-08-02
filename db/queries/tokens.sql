-- name: CreateToken :one
INSERT INTO tokens (user_id, access_token, refresh_token) VALUES ($1, $2, $3) RETURNING *;

-- name: GetToken :one
SELECT * FROM tokens WHERE user_id = $1;

-- name: DeleteToken :exec
DELETE FROM tokens WHERE user_id = $1;

-- name: UpdateToken :exec
UPDATE tokens 
SET access_token = $2, refresh_token = $3 
WHERE user_id = $1;

-- name: GetUserIDByAcsessToken :one
SELECT user_id FROM tokens WHERE access_token = $1;