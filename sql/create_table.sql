
CREATE TABLE IF NOT EXISTS fast_config (
       env VARCHAR(64) NOT NULL,
       name VARCHAR(64) NOT NULL,
       value TEXT NOT NULL,
       version BIGINT(20) NOT NULL,
       create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
       update_time TIMESTAMP NOT NULL,
       PRIMARY KEY (env, name),
       UNIQUE (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS fast_increment (
        name VARCHAR(64) NOT NULL,
        value BIGINT(20) NOT NULL,
        PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO fast_increment (name, value) VALUES ('fast_config_version', 0);
