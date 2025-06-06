import db from "../SQLite3/db.js";
import { saveLog } from '../SQLite3/logger.js'; // Import đúng đường
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import axios from "axios";
import jwt from "jsonwebtoken";
import CryptoJS from "crypto-js";

dotenv.config();
const saltRounds = parseInt(process.env.SALT_ROUNDS);
const KONG_ADMIN_URL = process.env.kong_admin_url;
const JWT_ACCESS_TOKEN_EXPIRES_IN =
  process.env.JWT_ACCESS_TOKEN_EXPIRES_IN || "15m";
const JWT_REFRESH_TOKEN_EXPIRES_IN_MINUTES =
  parseInt(process.env.JWT_REFRESH_TOKEN_EXPIRES_IN_MINUTES) || 30;

async function generateJWTToken(user, refresh_token = null) {
  if (!KONG_ADMIN_URL) {
    console.error("KONG_ADMIN_URL is not configured in .env");
    return res
      .status(500)
      .json({ error: "API Gateway integration is not configured." });
  }

  let consumerId;
  let kongJwtKey;
  let kongJwtSecret = user.secret;
  let kongJwtAlgorithm;

  try {
    // Ensure Kong Consumer exists
    try {
      const consumerRes = await axios.get(
        `${KONG_ADMIN_URL}/consumers/${encodeURIComponent(user.username)}`
      );
      consumerId = consumerRes.data.id;
    } catch (error) {
      console.error(
        "Kong: Error checking consumer",
        error.response?.data || error.message
      );
      throw {
        status: 500,
        message:
          "Error communicating with Kong Admin API while checking consumer.",
      };
    }

    // Attempt to GET existing JWT credentials for the consumer.
    let foundUsableExistingCredential = false;
    try {
      console.log(
        `Attempting to GET existing JWT credentials for consumer ID: ${consumerId}`
      );
      const listCredentialsResponse = await axios.get(
        `${KONG_ADMIN_URL}/consumers/${consumerId}/jwt`
      );

      if (
        listCredentialsResponse.data &&
        listCredentialsResponse.data.data &&
        listCredentialsResponse.data.data.length > 0
      ) {
        // Prefer HS256 and ensure secret is available
        const preferredCredential = listCredentialsResponse.data.data.find(
          (cred) => cred.algorithm === "HS256" && cred.key
        );

        if (preferredCredential) {
          console.log(
            `Found usable existing Kong JWT credential (HS256 with secret): ${preferredCredential.id}`
          );
          kongJwtKey = preferredCredential.key;
          kongJwtAlgorithm = preferredCredential.algorithm;
          foundUsableExistingCredential = true;
        } else {
          console.log(
            "No existing HS256 JWT credential with secret found via GET, or secret not returned."
          );
        }
      } else {
        console.log(
          `No existing JWT credentials found via GET for consumer ID: ${consumerId}`
        );
      }
    } catch (getErr) {
      console.warn(
        `Error trying to GET JWT credentials for consumer ID ${consumerId}: ${getErr.message}. Will proceed to create/ensure.`
      );
    }

    // If no usable existing credential was found, then POST to create/ensure one. POST response should include the secret.
    if (!foundUsableExistingCredential) {
      console.log(
        `No usable existing JWT credential found or GET did not provide necessary details. Posting to create/ensure JWT credentials for consumer ID: ${consumerId}`
      );
      const jwtCredentialsResponse = await axios.post(
        `${KONG_ADMIN_URL}/consumers/${consumerId}/jwt`,
        { algorithm: "HS256" },
        { headers: { "Content-Type": "application/json" } }
      );

      kongJwtKey = jwtCredentialsResponse.data.key;
      kongJwtSecret = jwtCredentialsResponse.data.secret;
      kongJwtAlgorithm = jwtCredentialsResponse.data.algorithm;
      console.log(
        `Received JWT credentials from POST. Key: ${kongJwtKey}, Algorithm: ${kongJwtAlgorithm}`
      );

      const sql = `UPDATE users SET secret = ? WHERE username = ?`;

      try {
        await new Promise((resolve, reject) => {
          db.run(sql, [kongJwtSecret, username], function (err) {
            if (err) {
              return reject(err);
            }
            resolve(this.changes);
          });
        });
      } catch (err) {
        // If updating the DB fails, rollback the credential on Kong
        console.error("Database error updating user secret:", err);
        try {
          await axios.delete(
            `${KONG_ADMIN_URL}/consumers/${consumerId}/jwt/${credentialId}`
          );
          console.log(
            `Rolled back (deleted) JWT credential ${credentialId} for consumer ${consumerId} on Kong due to DB failure.`
          );
        } catch (deleteErr) {
          console.error(
            `Failed to rollback JWT credential ${credentialId} on Kong:`,
            deleteErr.response?.data || deleteErr.message
          );
        }
        throw {
          status: 500,
          message: "Failed to update user secret in database.",
        };
      }
    }

    if (!kongJwtKey || !kongJwtSecret || !kongJwtAlgorithm) {
      console.error("Failed to retrieve complete JWT credentials from Kong:", {
        kongJwtKey,
        kongJwtSecret,
        kongJwtAlgorithm,
      });
      throw {
        status: 500,
        message: "Incomplete JWT credentials received from API Gateway.",
      };
    }
  } catch (kongError) {
    // This catches errors from consumer check or JWT credential operations
    const errorMessage =
      kongError.message ||
      "Failed to process authentication credentials with API Gateway.";
    const errorStatus = kongError.status || 500;
    console.error(
      `Kong interaction error during signin: Status ${errorStatus}, Message: ${errorMessage}`,
      kongError.response?.data || kongError
    );
    return res.status(errorStatus).json({
      error: errorMessage,
    });
  }

  // Generate Access Token
  const accessTokenPayload = {
    iss: kongJwtKey,
    sub: user.id,
    username: user.username,
  };
  const accessToken = jwt.sign(accessTokenPayload, kongJwtSecret, {
    algorithm: kongJwtAlgorithm,
    expiresIn: JWT_ACCESS_TOKEN_EXPIRES_IN,
  });

  // Generate Refresh Token
  const refreshToken = CryptoJS.lib.WordArray.random(40).toString(
    CryptoJS.enc.Hex
  );
  const refreshTokenHash = CryptoJS.SHA256(refreshToken).toString(
    CryptoJS.enc.Hex
  );
  const refreshTokenCreatedAt = new Date();
  let refreshTokenExpiresAt;
  if (refresh_token && refresh_token.expires_at) {
    // If refresh_token is provided and has expires_at, use its expires time
    refreshTokenExpiresAt = new Date(refresh_token.expires_at);
  } else if (!refresh_token) {
    // If no refresh_token is provided, set a default expiration time
    refreshTokenExpiresAt = new Date(refreshTokenCreatedAt);
    refreshTokenExpiresAt.setMinutes(
      refreshTokenExpiresAt.getMinutes() + JWT_REFRESH_TOKEN_EXPIRES_IN_MINUTES
    );
  } else {
    // If refresh_token is provided but no expires_at, return an error
    return res.status(400).json({
      error: "Refresh token must have an expires_at field.",
    });
  }

  // Store hashed Refresh Token in the database
  try {
    // Delete old refresh tokens for this user if any
    await new Promise((resolve, reject) => {
      db.run(
        "DELETE FROM refresh_tokens WHERE user_id = ?",
        [user.id],
        (err) => {
          if (err) {
            // Continue even if there is an error deleting old tokens
            console.warn(
              "Could not delete old refresh tokens for user:",
              user.id,
              err
            );
          }
          resolve();
        }
      );
    });
  } catch (dbError) {
    console.error("Critical error storing refresh token:", dbError);
  }
  try {
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO refresh_tokens (user_id, token_hash, kong_jwt_key, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        [
          user.id,
          refreshTokenHash,
          kongJwtKey,
          refreshTokenExpiresAt.toISOString(),
          refreshTokenCreatedAt.toISOString(),
        ],
        function (err) {
          if (err) {
            console.error("Database error storing refresh token:", err);
            return reject({
              status: 500,
              message: "Failed to store refresh token.",
            });
          }
          resolve(this.lastID);
        }
      );
    });
  } catch (dbError) {
    console.error("Critical error storing refresh token:", dbError);
    return res.status(500).json({
      error:
        dbError.message || "Could not complete signin due to internal error.",
    });
  }
  console.log(
    `Stored refresh token for user ${user.username}, accessToken: ${accessToken}, refreshToken: ${refreshToken}.`
  );
  // Return tokens
  return {
    accessToken: accessToken,
    refreshToken: refreshToken,
    token_type: "Bearer",
  };
}

export const signup = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }

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

    const KONG_ADMIN_URL = process.env.kong_admin_url;
    if (!KONG_ADMIN_URL) {
      throw {
        status: 500,
        message: "kong_admin_url is not configured in .env",
      };
    }

    let consumerId;
    let kongJwtKey;
    let kongJwtSecret;
    let kongJwtAlgorithm;

    try {
      const consumerRes = await axios.get(
        `${KONG_ADMIN_URL}/consumers/${encodeURIComponent(username)}`
      );
      consumerId = consumerRes.data.id;
      // Consumer exists in Kong but not in DB, so fetch or create JWT credentials
      try {
        const jwtCredentialsResponse = await axios.post(
          `${KONG_ADMIN_URL}/consumers/${consumerId}/jwt`,
          { algorithm: "HS256" },
          { headers: { "Content-Type": "application/json" } }
        );
        kongJwtKey = jwtCredentialsResponse.data.key;
        kongJwtSecret = jwtCredentialsResponse.data.secret;
        kongJwtAlgorithm = jwtCredentialsResponse.data.algorithm;
        console.log(
          `Received JWT credentials from POST. Key: ${kongJwtKey}, Algorithm: ${kongJwtAlgorithm}`
        );
      } catch (jwtError) {
        console.error(
          "Kong: Failed to create JWT credentials for existing consumer",
          jwtError.response?.data || jwtError.message
        );
        throw {
          status: 500,
          message:
            "Failed to create JWT credentials for existing Kong consumer.",
        };
      }
      // Continue to create user in local DB
    } catch (error) {
      if (error.response && error.response.status === 404) {
        // Consumer does not exist, create it
        try {
          const createConsumerRes = await axios.post(
            `${KONG_ADMIN_URL}/consumers`,
            { username: username },
            { headers: { "Content-Type": "application/json" } }
          );
          consumerId = createConsumerRes.data.id;

          const jwtCredentialsResponse = await axios.post(
            `${KONG_ADMIN_URL}/consumers/${consumerId}/jwt`,
            { algorithm: "HS256" },
            { headers: { "Content-Type": "application/json" } }
          );

          kongJwtKey = jwtCredentialsResponse.data.key;
          kongJwtSecret = jwtCredentialsResponse.data.secret;
          kongJwtAlgorithm = jwtCredentialsResponse.data.algorithm;
          console.log(
            `Received JWT credentials from POST. Key: ${kongJwtKey}, Algorithm: ${kongJwtAlgorithm}`
          );
        } catch (createError) {
          console.error(
            "Kong: Failed to create consumer",
            createError.response?.data || createError.message
          );
          throw { status: 500, message: "Failed to create Kong consumer." };
        }
      } else {
        console.error(
          "Kong: Error checking consumer",
          error.response?.data || error.message
        );
        throw {
          status: 500,
          message:
            "Error communicating with Kong Admin API while checking consumer.",
        };
      }
    }

    const sql = `INSERT INTO users (username, password_hash, secret) VALUES (?, ?, ?)`;

    await new Promise((resolve, reject) => {
      db.run(sql, [username, password_hash, kongJwtSecret], function (err) {
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

    saveLog({
      client_ip: req.ip,
      request_uri: req.originalUrl,
      status: 201, // hoặc res.statusCode nếu đã gọi res.status()
      response_time: 0.1, // nếu không đo được thì set tạm
      service: 'auth-service'
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

    // Generate JWT tokens
    const { accessToken, refreshToken, token_type } = await generateJWTToken(
      user
    );

    // Return tokens to client
    res.status(200).json({
      message: "User signed in successfully!",
      username: user.username,
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: token_type,
      expires_in: `${
        jwt.decode(accessToken).exp - Math.floor(Date.now() / 1000)
      } seconds`, // Countdown in seconds
    });

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

export const signout = async (req, res) => {
  
}

export const refreshAccessToken = async (req, res) => {
  try {
    const { refresh_token } = req.body;
    let user;
    if (!refresh_token) {
      return res.status(400).json({ error: "Refresh token is required." });
    }

    const refreshTokenHash = CryptoJS.SHA256(refresh_token).toString(
      CryptoJS.enc.Hex
    );

    const tokenData = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM refresh_tokens WHERE token_hash = ?",
        [refreshTokenHash],
        (err, row) => {
          if (err) {
            console.error("Database error during refresh token check:", err);
            return reject({
              status: 500,
              message: "Internal Server Error during token check.",
            });
          }
          resolve(row);
        }
      );
    });
    if (!tokenData) {
      return res
        .status(401)
        .json({ error: "Invalid or expired refresh token." });
    }
    if (new Date(tokenData.expires_at) < new Date()) {
      return res.status(401).json({ error: "Refresh token has expired." });
    } else {
      user = await new Promise((resolve, reject) => {
        db.get(
          "SELECT * FROM users WHERE id = ?",
          [tokenData.user_id],
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
    }
    // Generate new JWT tokens
    const { accessToken, refreshToken, token_type } = await generateJWTToken(
      user,
      tokenData
    );
    // Return new tokens to client
    res.status(200).json({
      message: "Access token refreshed successfully!",
      username: user.username,
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: token_type,
      expires_in: `${
        jwt.decode(accessToken).exp - Math.floor(Date.now() / 1000)
      } seconds`, // Countdown in seconds
    });
  } catch (error) {
    if (error.status) {
      return res.status(error.status).json({ error: error.message });
    }
    console.error("Error during access token refresh:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};
