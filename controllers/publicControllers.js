import db from "../SQLite3/db.js";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();
const saltRounds = parseInt(process.env.SALT_ROUNDS);

export const signup = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }

    // Check if user already exists
    const userExists = await new Promise((resolve, reject) => {
      db.get(
        "SELECT username FROM users WHERE username = ?",
        [username],
        (err, row) => {
          if (err) {
            console.error("Database error during user check:", err);
            return reject({
              status: 500,
              message: "Internal Server Error during user check.",
            });
          }
          resolve(!!row);
        }
      );
    });

    if (userExists) {
      return res.status(409).json({ error: "Username already exists." });
    }

    const password_hash = await bcrypt.hash(password, saltRounds);

    const sql = `INSERT INTO users (username, password_hash) VALUES (?, ?)`;

    await new Promise((resolve, reject) => {
      db.run(sql, [username, password_hash], function (err) {
        if (err) {
          console.error("Database error during signup:", err);
          return reject({
            status: 500,
            message: "Internal Server Error during database operation.",
          });
        }
        resolve(this.lastID);
      });
    });

    res.status(201).json({ message: "User signed up successfully!", username });
  } catch (error) {
    if (error.status) {
      res.status(error.status).json({ error: error.message });
    } else {
      console.error("Error during signup:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
};

export const signin = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }

    const user = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        (err, row) => {
          if (err) {
            console.error("Database error during user retrieval:", err);
            return reject({
              status: 500,
              message: "Internal Server Error during user retrieval.",
            });
          }
          resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid password." });
    }

    res.status(200).json({ message: "User signed in successfully!", username });
    console.log(`User ${username} signed in successfully.`);
  } catch (error) {
    if (error.status) {
      res.status(error.status).json({ error: error.message });
    } else {
      console.error("Error during signin:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
};
