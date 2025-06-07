import express from "express";
import { body, validationResult } from "express-validator";
import {
  signup,
  signin,
  refreshAccessToken,
} from "../controllers/publicControllers.js";

const router = express.Router();

router.get("/info", (req, res) => {
  console.log("Public endpoint accessed");
  res.json({
    message: "This is a public endpoint, accessible without authentication.",
  });
});

// Validation rules cho signin
const signinValidationRules = [
  body("username")
    .trim()             // Bỏ khoảng trắng đầu cuối
    .escape()           // Convert ký tự đặc biệt thành dạng an toàn (ví dụ < thành &lt;)
    .notEmpty()
    .withMessage("Username không được để trống")
    .isAlphanumeric()
    .withMessage("Username chỉ được chứa ký tự chữ và số"),

  body("password")
    .trim()
    .notEmpty()
    .withMessage("Password không được để trống")
    .escape(),          // Mặc dù password thường không escape, bạn cân nhắc vì password không nên bị thay đổi quá nhiều
];



// Middleware kiểm tra validation result
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.post("/signup", signup);
router.post("/signin", signinValidationRules, validate, signin);
router.post("/refresh", refreshAccessToken);

export default router;
