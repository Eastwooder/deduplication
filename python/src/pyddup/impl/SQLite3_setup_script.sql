DROP TABLE IF EXISTS devices;
CREATE TABLE devices (
  ID            INTEGER UNIQUE NOT NULL,
  CASECLUSTERID VARCHAR(60)    NOT NULL,
  METADATA      TEXT,
  PRIMARY KEY (id)
);

DROP TABLE IF EXISTS elements;
CREATE TABLE elements (
  SHA1      CHARACTER(40) DEFAULT NULL,
  SHA256    CHARACTER(64) DEFAULT NULL,
  MD5       CHARACTER(32) DEFAULT NULL,
  DEVICEID  SMALLINT      DEFAULT NULL,
  PATH      CLOB          DEFAULT NULL,
  FILESLACK BLOB          DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_elements_sha1
  ON elements (SHA1);
CREATE INDEX IF NOT EXISTS idx_elements_sha256
  ON elements (SHA256);
CREATE INDEX IF NOT EXISTS idx_elements_md5
  ON elements (MD5);

DROP TABLE IF EXISTS whitelist;
CREATE TABLE whitelist (
  SHA1   CHARACTER(40) DEFAULT NULL,
  SHA256 CHARACTER(64) DEFAULT NULL,
  MD5    CHARACTER(32) DEFAULT NULL,
  NOTE   CLOB          DEFAULT NULL
);

DROP VIEW IF EXISTS get_unique_elements_all;
DROP VIEW IF EXISTS get_unique_elements_sha1;
DROP VIEW IF EXISTS get_unique_elements_sha256;
DROP VIEW IF EXISTS get_unique_elements_md5;

CREATE VIEW get_unique_elements_sha1 AS
  SELECT
    SHA1,
    SHA256,
    MD5,
    DEVICEID,
    PATH,
    FILESLACK
  FROM elements e
  WHERE e.DEVICEID = (SELECT min(em.DEVICEID)
                      FROM elements em
                      WHERE e.SHA1 = em.SHA1)
        AND e.SHA1 NOT IN (SELECT w.SHA1
                           FROM whitelist w
                           WHERE e.SHA1 = w.SHA1)
  GROUP BY e.SHA1;

CREATE VIEW get_unique_elements_sha256 AS
  SELECT
    SHA1,
    SHA256,
    MD5,
    DEVICEID,
    PATH,
    FILESLACK
  FROM elements e
  WHERE e.DEVICEID = (SELECT min(em.DEVICEID)
                      FROM elements em
                      WHERE e.SHA256 = em.SHA256)
        AND e.SHA256 NOT IN (SELECT w.SHA256
                             FROM whitelist w
                             WHERE e.SHA256 = w.SHA256)
  GROUP BY e.SHA256;

CREATE VIEW get_unique_elements_md5 AS
  SELECT
    SHA1,
    SHA256,
    MD5,
    DEVICEID,
    PATH,
    FILESLACK
  FROM elements e
  WHERE e.DEVICEID = (SELECT min(em.DEVICEID)
                      FROM elements em
                      WHERE e.MD5 = em.MD5)
        AND e.MD5 NOT IN (SELECT w.MD5
                             FROM whitelist w
                             WHERE e.MD5 = w.MD5)
  GROUP BY e.MD5;

CREATE VIEW get_unique_elements_all AS
  SELECT
    SHA1,
    SHA256,
    MD5,
    DEVICEID,
    PATH,
    FILESLACK
  FROM get_unique_elements_sha1
  UNION
  SELECT
    SHA1,
    SHA256,
    MD5,
    DEVICEID,
    PATH,
    FILESLACK
  FROM get_unique_elements_sha256
  UNION
  SELECT
    SHA1,
    SHA256,
    MD5,
    DEVICEID,
    PATH,
    FILESLACK
  FROM get_unique_elements_md5;