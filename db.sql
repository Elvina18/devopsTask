CREATE DATABASE task;
USE task;

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
);

-- Create the recipes table
CREATE TABLE IF NOT EXISTS recipes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  recipe_name VARCHAR(255) NOT NULL,
  ingredients TEXT NOT NULL,
  user_id INT NOT NULL
);
