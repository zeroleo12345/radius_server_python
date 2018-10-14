CREATE TABLE `user` (
    `username` varchar(255) NOT NULL,
    `password` varchar(255) NOT NULL
);
CREATE UNIQUE INDEX user_username ON `user`(username);

INSERT INTO `user`(username, password) VALUES('zhoulixin', 'zhoulixin');
INSERT INTO `user`(username, password) VALUES('zhouliying', 'zhouliying');
INSERT INTO `user`(username, password) VALUES('zhangfengjian', 'zhangfengjian');
