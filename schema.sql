--- TABLES ---

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_admin BOOLEAN DEFAULT FALSE
);

CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE post_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    operation TEXT NOT NULL,  -- 'create' and 'delete'
    time_stamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);


--- TRIGGERS ---

-- Used to log that a post has been created
CREATE TRIGGER trig_log_post_created
AFTER INSERT ON posts
FOR EACH ROW
BEGIN
    INSERT INTO post_logs (user_id, post_id, operation)
    VALUES (NEW.user_id, NEW.id, 'create');
END;

-- Used to log that a post has been deleted
CREATE TRIGGER trig_log_post_deleted
BEFORE DELETE ON posts
FOR EACH ROW
BEGIN
    INSERT INTO post_logs (user_id, post_id, operation)
    VALUES (OLD.user_id, OLD.id, 'delete');
END;