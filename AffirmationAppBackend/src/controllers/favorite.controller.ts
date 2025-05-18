import { Request, Response } from "express";
import prisma from "../prisma"; // Assuming prisma client is exported from a 'prisma.ts' or similar in this directory or root

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    // other user properties if available from authMiddleware
  };
}

export const addFavorite = async (req: AuthenticatedRequest, res: Response) => {
  const { affirmationId } = req.body;
  const userId = req.user?.id;

  if (!userId) {
    return res.status(401).json({ message: "User not authenticated" });
  }

  if (!affirmationId) {
    return res.status(400).json({ message: "Affirmation ID is required" });
  }

  try {
    const existingFavorite = await prisma.favorite.findUnique({
      where: {
        userId_affirmationId: {
          userId,
          affirmationId,
        },
      },
    });

    if (existingFavorite) {
      return res.status(409).json({ message: "Affirmation already favorited" });
    }

    const favorite = await prisma.favorite.create({
      data: {
        userId,
        affirmationId,
      },
    });
    res.status(201).json(favorite);
  } catch (error: any) {
    console.error("Error adding favorite:", error);
    res
      .status(500)
      .json({ message: "Error adding favorite", error: error.message });
  }
};

export const removeFavorite = async (
  req: AuthenticatedRequest,
  res: Response
) => {
  const { affirmationId } = req.params;
  const userId = req.user?.id;

  if (!userId) {
    return res.status(401).json({ message: "User not authenticated" });
  }

  if (!affirmationId) {
    return res.status(400).json({ message: "Affirmation ID is required" });
  }

  try {
    await prisma.favorite.delete({
      where: {
        userId_affirmationId: {
          userId,
          affirmationId,
        },
      },
    });
    res.status(204).send(); // No content
  } catch (error: any) {
    // Prisma throws an error if the record to delete is not found
    if (error.code === "P2025") {
      return res.status(404).json({ message: "Favorite not found" });
    }
    console.error("Error removing favorite:", error);
    res
      .status(500)
      .json({ message: "Error removing favorite", error: error.message });
  }
};

export const getFavorites = async (
  req: AuthenticatedRequest,
  res: Response
) => {
  const userId = req.user?.id;

  if (!userId) {
    return res.status(401).json({ message: "User not authenticated" });
  }

  try {
    const favorites = await prisma.favorite.findMany({
      where: {
        userId,
      },
      orderBy: {
        createdAt: "desc", // Optional: order by creation date
      },
    });
    res.status(200).json(favorites);
  } catch (error: any) {
    console.error("Error fetching favorites:", error);
    res
      .status(500)
      .json({ message: "Error fetching favorites", error: error.message });
  }
};
