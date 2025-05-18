import { Router } from "express";
import {
  addFavorite,
  removeFavorite,
  getFavorites,
} from "../controllers/favorite.controller";
import { protect } from "../middleware/auth.middleware"; // Importing the correct middleware name

const router = Router();

// All favorite routes require authentication
router.use(protect);

router.post("/", addFavorite);
router.get("/", getFavorites);
router.delete("/:affirmationId", removeFavorite);

export default router;
