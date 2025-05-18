import express from "express";
import { getUserProfile } from "../controllers/user.controller"; // Import controller function
import { protect } from "../middleware/auth.middleware"; // Import the auth middleware

const router = express.Router();

// Protected route to get the logged-in user's profile
// The 'protect' middleware ensures only authenticated users can access this route
router.get("/profile", protect, getUserProfile);

export default router;
