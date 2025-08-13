import { Request, Response } from "express";
import streamifier from "streamifier";
import cloudinary from "../config/cloudinary";
import User from "../models/user.model";

export const updateProfilePhoto = async (req: Request, res: Response) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });

    const streamUpload = (buffer: Buffer) => {
      return new Promise<{ secure_url: string }>((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: "profile_photos" },
          (error, result) => {
            if (result) resolve(result as any);
            else reject(error);
          }
        );
        streamifier.createReadStream(buffer).pipe(stream);
      });
    };

    const result = await streamUpload(req.file.buffer);

    const user = await User.findByIdAndUpdate(
      req.user?._id,
      { avatarUrl: result.secure_url },
      { new: true }
    );
    return res.json({ avatarUrl: user?.avatarUrl });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
};