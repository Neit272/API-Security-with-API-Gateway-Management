import express from "express";
import { body, validationResult } from "express-validator";
import {
  signup,
  signin,
  refresh, // CHANGE: từ refreshAccessToken thành refresh
  signout,
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
    .trim()
    .escape()
    .notEmpty()
    .withMessage("Username không được để trống")
    .isAlphanumeric()
    .withMessage("Username chỉ được chứa ký tự chữ và số"),

  body("password")
    .trim()
    .notEmpty()
    .withMessage("Password không được để trống")
    .escape(),
];

// Validation rules cho signup
const signupValidationRules = [
  body("username")
    .trim()
    .escape()
    .notEmpty()
    .withMessage("Username không được để trống")
    .isLength({ min: 3, max: 20 })
    .withMessage("Username phải từ 3-20 ký tự")
    .isAlphanumeric()
    .withMessage("Username chỉ được chứa ký tự chữ và số"),

  body("password")
    .trim()
    .notEmpty()
    .withMessage("Password không được để trống")
    .isLength({ min: 8 })
    .withMessage("Password phải ít nhất 8 ký tự")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("Password phải có ít nhất 1 chữ thường, 1 chữ hoa, 1 số")
    .escape(),
];

// Validation rules cho refresh
const refreshValidationRules = [
  body("refresh_token")
    .trim()
    .notEmpty()
    .withMessage("Refresh token không được để trống")
    .escape(),
];

// Validation rules cho signout
const signoutValidationRules = [
  body("refresh_token")
    .trim()
    .notEmpty()
    .withMessage("Refresh token không được để trống")
    .escape(),
];

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.post("/signup", signupValidationRules, validate, signup);
router.post("/signin", signinValidationRules, validate, signin);
router.post("/refresh", refreshValidationRules, validate, refresh);
router.post("/signout", signoutValidationRules, validate, signout);

export default router;
