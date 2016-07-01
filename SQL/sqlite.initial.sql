CREATE TABLE login_security_bans (
  ip varchar(39) NOT NULL,
  created datetime NOT NULL,
  expires datetime NOT NULL
);

CREATE INDEX ix_login_security_bans_ip ON login_security_bans(ip);

CREATE TABLE login_security_failures (
  ip varchar(39) NOT NULL,
  dt datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  mailbox varchar(128) DEFAULT '',
  PRIMARY KEY (`ip`,`dt`)
);

CREATE INDEX ix_login_security_failures ON login_security_failures(ip, dt);
