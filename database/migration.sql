CREATE TABLE IF NOT EXISTS users (
    id SERIAL NOT NULL PRIMARY KEY,
    username VARCHAR(20) NOT NULL UNIQUE,
    email VARCHAR(25) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_email_verified BOOLEAN DEFAULT false,
    is_admin BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS records (
    id SERIAL NOT NULL PRIMARY KEY,
    amount INT NOT NULL,
    description VARCHAR(100) NOT NULL,
    category VARCHAR(15) NOT NULL,
    payment_method VARCHAR(10) NOT NULL
);