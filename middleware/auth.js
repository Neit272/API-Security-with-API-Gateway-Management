import jwt from "jsonwebtoken";
import CryptoJS from "crypto-js";
import db from "../SQLite3/db.js";

const checkBlacklist = async (tokenHash) => {
  return new Promise((resolve) => {
    db.get(
      "SELECT id FROM blacklisted_tokens WHERE token_hash = ? AND expires_at > datetime('now')",
      [tokenHash],
      (err, row) => {
        if (err) {
          console.error("Error checking blacklist:", err);
          resolve(false); // Cho phép tiếp tục nếu DB error
        }
        resolve(!!row); // true nếu token bị blacklist
      }
    );
  });
};

let lastCleanup = Date.now();
const CLEANUP_INTERVAL = 1000 * 60 * 60; // 1 hour in milliseconds

export const verifyTokenAndBlacklist = async (req, res, next) => {
  try {
    // LAZY CLEANUP - Check if it's time to cleanup
    if (Date.now() - lastCleanup > CLEANUP_INTERVAL) {
      console.log("Running lazy cleanup of expired tokens...");

      // Run cleanup in background (non-blocking)
      cleanupExpiredBlacklistedTokens()
        .then((deletedCount) => {
          console.log(
            `Lazy cleanup completed. Removed ${deletedCount} expired tokens.`
          );
        })
        .catch((err) => {
          console.error("Lazy cleanup failed:", err);
        });

      lastCleanup = Date.now();
    }

    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No valid authorization header" });
    }

    const token = authHeader.substring(7); // Remove "Bearer "

    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    // Check if token is blacklisted
    const tokenHash = CryptoJS.SHA256(token).toString(CryptoJS.enc.Hex);
    const isBlacklisted = await checkBlacklist(tokenHash);

    if (isBlacklisted) {
      return res.status(401).json({ error: "Token has been revoked" });
    }

    // Token is not blacklisted, continue to Kong
    console.log(`Token ${tokenHash.substring(0, 8)}... passed blacklist check`);
    next();
  } catch (error) {
    console.error("Token blacklist check error:", error);
    res
      .status(500)
      .json({ error: "Internal server error during token validation" });
  }
};

export const cleanupExpiredBlacklistedTokens = async () => {
  return new Promise((resolve, reject) => {
    db.run(
      "DELETE FROM blacklisted_tokens WHERE expires_at <= datetime('now')",
      function (err) {
        if (err) {
          console.error("Error cleaning up expired blacklisted tokens:", err);
          return reject(err);
        }
        console.log(`Cleaned up ${this.changes} expired blacklisted tokens`);
        resolve(this.changes);
      }
    );
  });
};
