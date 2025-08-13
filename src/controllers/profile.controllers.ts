import { Request, Response } from "express";
import cloudinary from "../config/cloudinary";
import User from "../models/user.model";

export const updateProfilePhoto = async (req: Request, res: Response) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload_stream(
      { folder: "profile_photos" },
      async (error, result) => {
        if (error || !result) {
          return res.status(500).json({ message: "Cloudinary upload failed" });
        }
        // Update user
        const user = await User.findByIdAndUpdate(
          req.user?._id,
          { avatarUrl: result.secure_url },
          { new: true }
        );
        return res.json({ avatarUrl: user?.avatarUrl });
      }
    );
    // Pipe file buffer to Cloudinary
    if (req.file && req.file.buffer) {
      require("streamifier").createReadStream(req.file.buffer).pipe(result);
    }
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
};