-- MySQL dump 10.13  Distrib 5.6.22, for Linux (x86_64)
--
-- Host: localhost    Database: db_mapping
-- ------------------------------------------------------
-- Server version	5.6.22

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `db_setting`
--

DROP TABLE IF EXISTS `db_setting`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `db_setting` (
  `database_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host_name` varchar(255) NOT NULL,
  `port_number` int(11) NOT NULL DEFAULT '3306',
  `database_name` varchar(255) NOT NULL,
  `user` varchar(32) NOT NULL,
  `passwd` varchar(32) NOT NULL,
  `active` tinyint(4) NOT NULL DEFAULT '1',
  `master_sid` int(11) NOT NULL,
  PRIMARY KEY (`database_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `db_setting`
--

LOCK TABLES `db_setting` WRITE;
/*!40000 ALTER TABLE `db_setting` DISABLE KEYS */;
INSERT INTO `db_setting` VALUES (1,'127.0.0.1',3306,'xxfs_0','root','376504340',1,0),(2,'127.0.0.1',3306,'xxfs_1','root','376504340',1,0),(3,'127.0.0.1',3306,'xxfs_slave_0','root','376504340',0,1),(4,'127.0.0.1',3306,'xxfs_slave_0','root','376504340',0,1);
/*!40000 ALTER TABLE `db_setting` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `kind_setting`
--

DROP TABLE IF EXISTS `kind_setting`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `kind_setting` (
  `table_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `table_name` varchar(255) NOT NULL,
  `status` enum('federated','universal') NOT NULL DEFAULT 'universal',
  `column_name` varchar(255) DEFAULT NULL,
  `next_id` bigint(20) DEFAULT '0',
  `increment_column` varchar(256) DEFAULT NULL,
  `table_num` int(11) NOT NULL,
  PRIMARY KEY (`table_id`),
  UNIQUE KEY `table_name` (`table_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `kind_setting`
--

LOCK TABLES `kind_setting` WRITE;
/*!40000 ALTER TABLE `kind_setting` DISABLE KEYS */;
INSERT INTO `kind_setting` VALUES (1,'xxfs_user','universal','uid',1901,'uid',2);
/*!40000 ALTER TABLE `kind_setting` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `table_setting`
--

DROP TABLE IF EXISTS `table_setting`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `table_setting` (
  `table_name` varchar(255) NOT NULL,
  `no` int(11) NOT NULL,
  `database_id` int(10) unsigned NOT NULL,
  UNIQUE KEY `kind` (`table_name`,`no`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `table_setting`
--

LOCK TABLES `table_setting` WRITE;
/*!40000 ALTER TABLE `table_setting` DISABLE KEYS */;
INSERT INTO `table_setting` VALUES ('xxfs_user',0,1),('xxfs_user',1,2);
/*!40000 ALTER TABLE `table_setting` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2016-05-14 23:15:05
