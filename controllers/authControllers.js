import bcrypt from "bcryptjs";
import db from "../SQLite3/db.js";
import axios from "axios";
import dotenv from "dotenv";
import CryptoJS from "crypto-js";

dotenv.config();

async function authenticateUserWithBasicAuth(req) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.toLowerCase().startsWith("basic")) {
    return res
      .status(401)
      .json({ error: "Unauthorized: Basic authentication required." });
  }

  const base64Credentials = authHeader.substring(6);
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "ascii"
  );
  const [username, password] = credentials.split(":");

  if (!username || !password) {
    return res.status(401).json({
      error: "Unauthorized: Invalid authentication credentials format.",
    });
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
    return res
      .status(401)
      .json({ error: "Unauthorized: Invalid username or password." });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);

  if (!isPasswordValid) {
    return res
      .status(401)
      .json({ error: "Unauthorized: Invalid username or password." });
  }

  return user;
}

export const getApiKeyViaBasicAuth = async (req, res) => {
  try {
    const user = await authenticateUserWithBasicAuth(req);
    const username = user.username;

    const newApiKey = CryptoJS.lib.WordArray.random(32).toString(
      CryptoJS.enc.Hex
    );

    // --- Store and Provision the API Key in Kong ---

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

    // --- End Kong Provisioning ---

    res.status(200).json({
      message: "API key generated successfully for user: " + username,
      apiKey: newApiKey,
    });
  } catch (error) {
    if (error.status) {
      return res.status(error.status).json({ error: error.message });
    }
    console.error("Error in getApiKeyViaBasicAuth:", error);
    res.status(500).json({
      error: "Internal Server Error while processing API key request.",
    });
  }
};
