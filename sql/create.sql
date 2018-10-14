CREATE TABLE `user` (
    `id` INTEGER PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL,
    `password` VARCHAR(255) NOT NULL
);
CREATE UNIQUE INDEX user_username ON `user`(username);

INSERT INTO `user`(id, username, password) VALUES(NULL, 'zhoulixin', 'zhoulixin');
INSERT INTO `user`(id, username, password) VALUES(NULL, 'zhouliying', 'zhouliying');
INSERT INTO `user`(id, username, password) VALUES(NULL, 'zhangfengjian', 'zhangfengjian');
