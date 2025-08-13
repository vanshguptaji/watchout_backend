import { Request, Response, NextFunction } from "express";
import { ApiError } from "../utils/ApiError";
import { asyncHandler } from "../utils/asyncHandler";
import jwt from "jsonwebtoken";
import User from "../models/user.model";

interface DecodedToken {
  _id: string;
  iat?: number;
  exp?: number;
}

export const verifyJWT = asyncHandler(async (req: Request & { user?: any }, res: Response, next: NextFunction) => {
  try {
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
    // console.log(token);

    if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }

    const decodeToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!) as DecodedToken;

    const user = await User.findById(decodeToken._id).select("-password -refreshToken");

    if (!user) {
      throw new ApiError(401, "Invalid token");
    }

    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, (error as Error)?.message || "Invalid token");
  }
});