import express from "express";
import publicRoutes from "./public.js";
import apiRoutes from "./apikey.js";
import jwtRoutes from "./jwt.js";
import authRoutes from "./auth.js";
const router = express.Router();

router.use("/public", publicRoutes);
router.use("/key", apiRoutes);
router.use("/jwt", jwtRoutes);
router.use("/auth", authRoutes);

export default router;
