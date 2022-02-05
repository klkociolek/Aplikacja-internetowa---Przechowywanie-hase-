DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS saved;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT NOT NULL,
    password BLOB NOT NULL,
    salt BLOB NOT NULL,
    master blob not null
);



CREATE TABLE saved (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    password TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
