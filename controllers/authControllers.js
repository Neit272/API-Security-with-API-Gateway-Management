import bcrypt from "bcryptjs";
import db from "../SQLite3/db.js";
import axios from "axios";
import dotenv from "dotenv";
import CryptoJS from "crypto-js";
import jwt from "jsonwebtoken";

dotenv.config();

// Chuẩn hóa Error/Success Response
const standardErrorResponse = (res, status, message, details = null) => {
  const response = {
    success: false,
    error: message,
  };

  if (details) {
    response.details = details;
  }

  return res.status(status).json(response);
};

const standardSuccessResponse = (res, status, message, data = null) => {
  const response = {
    success: true,
    message: message,
  };

  if (data) {
    Object.assign(response, data);
  }

  return res.status(status).json(response);
};

async function authenticateUserWithBasicAuth(req, res) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.toLowerCase().startsWith("basic")) {
    throw { status: 401, message: "Basic authentication required." };
  }

  const base64Credentials = authHeader.substring(6);
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "ascii"
  );
  const [username, password] = credentials.split(":");

  if (!username || !password) {
    throw {
      status: 401,
      message: "Invalid authentication credentials format.",
    };
  }

  const user = await new Promise((resolve, reject) => {
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
      if (err) {
        console.error(
          "Database error during user retrieval for API key generation:",
          err
        );
        return reject({
          status: 500,
          message: "Internal Server Error during user retrieval.",
        });
      }
      resolve(row);
    });
  });

  if (!user) {
    throw { status: 401, message: "Invalid username or password." };
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);

  if (!isPasswordValid) {
    throw { status: 401, message: "Invalid username or password." };
  }

  return user;
}

export const getApiKeyViaBasicAuth = async (req, res) => {
  try {
    const user = await authenticateUserWithBasicAuth(req, res);
    const username = user.username;

    const newApiKey = CryptoJS.lib.WordArray.random(32).toString(
      CryptoJS.enc.Hex
    );

    const KONG_ADMIN_URL = process.env.kong_admin_url;
    if (!KONG_ADMIN_URL) {
      throw {
        status: 500,
        message: "kong_admin_url is not configured in .env",
      };
    }

    // Ensure Kong Consumer exists for this user
    let consumerId;
    try {
      const consumerRes = await axios.get(
        `${KONG_ADMIN_URL}/consumers/${encodeURIComponent(username)}`
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

    try {
      // Get all key-auth credentials for this consumer
      const keyauthRes = await axios.get(
        `${KONG_ADMIN_URL}/consumers/${consumerId}/key-auth`
      );
      const keyauthList = keyauthRes.data.data || [];
      // Delete all existing key-auth credentials (if any)
      for (const cred of keyauthList) {
        await axios.delete(
          `${KONG_ADMIN_URL}/consumers/${consumerId}/key-auth/${cred.id}`
        );
      }
    } catch (keyAuthError) {
      console.error(
        "Kong: Failed to delete API key",
        keyAuthError.response?.data || keyAuthError.message
      );
      throw { status: 500, message: "Failed to delete API key in Kong." };
    }
    // Add the API key to this consumer's key-auth credentials
    try {
      await axios.post(
        `${KONG_ADMIN_URL}/consumers/${consumerId}/key-auth`,
        { key: newApiKey },
        { headers: { "Content-Type": "application/json" } }
      );
    } catch (keyAuthError) {
      console.error(
        "Kong: Failed to provision API key",
        keyAuthError.response?.data || keyAuthError.message
      );
      throw { status: 500, message: "Failed to provision API key in Kong." };
    }

    // Chuẩn hóa API Key response format
    return standardSuccessResponse(res, 200, "API key generated successfully", {
      username: username,
      apiKey: newApiKey,
      // Thêm các field alternative để dashboard có thể đọc
      api_key: newApiKey,
      key: newApiKey,
    });
  } catch (error) {
    return standardErrorResponse(
      res,
      error.status || 500,
      error.message || "Internal Server Error while processing API key request."
    );
  }
};

// Thêm JWT-based API Key method (alternative)
export const getApiKeyViaJWT = async (req, res) => {
  try {
    // Extract JWT from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw { status: 401, message: "JWT token required." };
    }

    const token = authHeader.substring(7);

    // Decode JWT to get username (không verify vì Kong đã verify)
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.username) {
      throw { status: 401, message: "Invalid JWT token." };
    }

    const username = decoded.username;

    // Get user from database
    const user = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        (err, row) => {
          if (err) {
            console.error("Database error during user retrieval:", err);
            return reject({ status: 500, message: "Internal Server Error." });
          }
          resolve(row);
        }
      );
    });

    if (!user) {
      throw { status: 404, message: "User not found." };
    }

    const newApiKey = CryptoJS.lib.WordArray.random(32).toString(
      CryptoJS.enc.Hex
    );

    const KONG_ADMIN_URL = process.env.kong_admin_url;
    if (!KONG_ADMIN_URL) {
      throw {
        status: 500,
        message: "kong_admin_url is not configured in .env",
      };
    }

    // Ensure Kong Consumer exists for this user
    let consumerId;
    try {
      const consumerRes = await axios.get(
        `${KONG_ADMIN_URL}/consumers/${encodeURIComponent(username)}`
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

    try {
      // Get all key-auth credentials for this consumer
      const keyauthRes = await axios.get(
        `${KONG_ADMIN_URL}/consumers/${consumerId}/key-auth`
      );
      const keyauthList = keyauthRes.data.data || [];
      // Delete all existing key-auth credentials (if any)
      for (const cred of keyauthList) {
        await axios.delete(
          `${KONG_ADMIN_URL}/consumers/${consumerId}/key-auth/${cred.id}`
        );
      }
    } catch (keyAuthError) {
      console.error(
        "Kong: Failed to delete API key",
        keyAuthError.response?.data || keyAuthError.message
      );
      throw { status: 500, message: "Failed to delete API key in Kong." };
    }
    // Add the API key to this consumer's key-auth credentials
    try {
      await axios.post(
        `${KONG_ADMIN_URL}/consumers/${consumerId}/key-auth`,
        { key: newApiKey },
        { headers: { "Content-Type": "application/json" } }
      );
    } catch (keyAuthError) {
      console.error(
        "Kong: Failed to provision API key",
        keyAuthError.response?.data || keyAuthError.message
      );
      throw { status: 500, message: "Failed to provision API key in Kong." };
    }

    return standardSuccessResponse(
      res,
      200,
      "API key generated successfully via JWT",
      {
        username: username,
        apiKey: newApiKey,
        api_key: newApiKey,
        key: newApiKey,
      }
    );
  } catch (error) {
    return standardErrorResponse(
      res,
      error.status || 500,
      error.message || "Internal Server Error."
    );
  }
};
