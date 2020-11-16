CREATE DATABASE `trade` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `broadband_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `openid` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `nickname` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `headimgurl` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `username` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_enable` tinyint(1) NOT NULL,
  `role` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `expired_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `openid` (`openid`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=124 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


insert into broadband_user(openid, nickname, headimgurl, username, password, is_enable, role, created_at, updated_at, expired_at) values('fake_openid_1', 'Lyn', 'https://thirdwx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTLX8xKmNq5vZOcmYHUWh7lOEBAKicyCHXPC0yN12yxt6rtDeicR7DCiaYwZ65cTKXNkibk6yp2qsEfXdA/132', 'zhoulixin', 'zhoulixin', 1, 'user', '2018-11-03 09:33:34.660780', '2020-03-28 23:20:54.415637',  '2099-09-01 08:39:25.818951');
insert into broadband_user(openid, nickname, headimgurl, username, password, is_enable, role, created_at, updated_at, expired_at) values('fake_openid_2', 'Lyn', 'https://thirdwx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTLX8xKmNq5vZOcmYHUWh7lOEBAKicyCHXPC0yN12yxt6rtDeicR7DCiaYwZ65cTKXNkibk6yp2qsEfXdA/132', 'testuser', 'password', 1, 'user', '2018-11-03 09:33:34.660780', '2020-03-28 23:20:54.415637',  '2099-09-01 08:39:25.818951');
