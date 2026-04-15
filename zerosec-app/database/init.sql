
DROP DATABASE IF EXISTS sql_injection_demo;
CREATE DATABASE sql_injection_demo;
USE sql_injection_demo;

CREATE TABLE users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(30) NOT NULL,
    password VARCHAR(130) NOT NULL,
    email VARCHAR(30) NOT NULL
);
INSERT INTO users (username, password, email) VALUES ('jhondoe', '916a0ae0522a9656d919eda2aceb6520c6c026536f2cc5218ff3340a18003bdba1ec187cc3c75e4f7ce9bbd435cab613deb2a84ec78fe6566e5b365886bf57b4', 'johndoe@zerosec.com');