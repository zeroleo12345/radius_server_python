CREATE TABLE `user` (
    `id` INTEGER PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `is_valid` INTEGER default 1
);
CREATE UNIQUE INDEX user_username ON `user`(username);

INSERT INTO `user`(id, username, password, is_valid) VALUES(NULL, 'zhoulixin', 'zhoulixin', 1);
INSERT INTO `user`(id, username, password, is_valid) VALUES(NULL, 'zhouliying', 'zhouliying', 1);
INSERT INTO `user`(id, username, password, is_valid) VALUES(NULL, 'zhangfengjian', 'zhangfengjian', 1);
