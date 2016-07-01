--
-- Table structure for table `login_security_bans`
--

DROP TABLE IF EXISTS `login_security_bans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_security_bans` (
  `ip` varchar(39) NOT NULL,
  `created` datetime NOT NULL,
  `expires` datetime NOT NULL,
  PRIMARY KEY (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `login_security_failures`
--

DROP TABLE IF EXISTS `login_security_failures`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_security_failures` (
  `ip` varchar(39) NOT NULL,
  `dt` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `mailbox` varchar(128) DEFAULT '',
  PRIMARY KEY (`ip`,`dt`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
