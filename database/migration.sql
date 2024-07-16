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
    payment_method VARCHAR(10) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plans (
    id SERIAL NOT NULL PRIMARY KEY,
    name VARCHAR(10) NOT NULL UNIQUE,
    description VARCHAR(100) NOT NULL,
    price INT NOT NULL UNIQUE,
    discount INT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(255) NOT NULL,
    amount NUMERIC NOT NULL,
    currency VARCHAR(10) NOT NULL,
    receipt VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

