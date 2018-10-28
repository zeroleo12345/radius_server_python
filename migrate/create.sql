CREATE TABLE `user` (
    `id` INTEGER PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `expired_at` DATETIME
);
CREATE UNIQUE INDEX user_username ON `user`(username);

INSERT INTO `user`(id, username, password, expired_at) VALUES(NULL, 'zhoulixin', 'zhoulixin', '2099-01-01 00:00:00');
INSERT INTO `user`(id, username, password, expired_at) VALUES(NULL, 'zhouliying', 'zhouliying', '2099-01-01 00:00:00');
INSERT INTO `user`(id, username, password, expired_at) VALUES(NULL, 'zhangfengjian', 'zhangfengjian', '2099-01-01 00:00:00');
