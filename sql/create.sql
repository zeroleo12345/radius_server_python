CREATE TABLE `user` (
    `id` bigint unsigned auto_increment PRIMARY KEY,
    `username` varchar(255) NOT NULL,
    `password` varchar(255) NOT NULL,
    `is_active` int unsigned,
    `role` varchar(32) NOT NULL
);
CREATE UNIQUE INDEX user_username ON `user`(username);
