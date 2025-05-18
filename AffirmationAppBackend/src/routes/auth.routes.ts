import express from "express";
import  {registerUser} from "../controllers/auth.controller";
import {loginUser}  from "../controllers/auth.controller"; // Import controller functions

const router = express.Router();

// Public routes for authentication
router.post("/register", registerUser); // Route for user registration
router.post("/login", loginUser); // Route for user login

export default router;
