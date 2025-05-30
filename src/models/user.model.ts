import mongoose, { Schema, Model } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { IUser } from "../types/user.types";
import dotenv from "dotenv";
dotenv.config();

const userSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
    },
    online: {
      type: Boolean,
      default: false,
    },
    followers: [
      {
        userId: { type: Schema.Types.ObjectId, ref: "User" },
        followedAt: { type: Date, default: Date.now },
      },
    ],
    following: [
      {
        userId: { type: Schema.Types.ObjectId, ref: "User" },
      },
    ],
    refreshToken: {
      type: String,
    },
    role: {
      type: String,
      enum: ["admin", "participant"],
      default: "participant",
    },
    profilePicture: {
      type: String,
      default: "",
    },
    profile: {
      name: { type: String },
      institution: { type: String },
      country: { type: String },
      avatarUrl: { type: String },
      bio: { type: String },
    },
    rating: {
      type: Number,
      default: 1000,
    }
  },
  { timestamps: true }
);

userSchema.pre<IUser>("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  if (obj.role === "admin") {
    delete obj.rating;
    delete obj.contestsParticipated;
    delete obj.solvedProblems;
  }
  return obj;
};

userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  if (obj.role === "participant") {
    delete obj.contestsCreated;
  }
  return obj;
};

userSchema.methods.isPasswordCorrect = async function (
  password: string
): Promise<boolean> {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function (): string {
  const secret = process.env.ACCESS_TOKEN_SECRET;
  // console.log(secret);
  if (!secret) {
    throw new Error("ACCESS_TOKEN_SECRET is not defined");
  }
  //merging with main
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
    },
    secret,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        ? process.env.ACCESS_TOKEN_EXPIRY
        : undefined,
      algorithm: "HS256",
    } as jwt.SignOptions
  );
};

userSchema.methods.generateRefreshToken = function (): string {
  const secret = process.env.REFRESH_TOKEN_SECRET;
  // console.log(parseInt(process.env.REFRESH_TOKEN_EXPIRY || "0"));
  // console.log(secret);
  if (!secret) {
    throw new Error("REFRESH_TOKEN_SECRET is not defined");
  }

  return jwt.sign(
    {
      _id: this._id,
    },
    secret,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        ? process.env.REFRESH_TOKEN_EXPIRY
        : undefined,
      algorithm: "HS256",
    } as jwt.SignOptions
  );
};

const User: Model<IUser> = mongoose.model<IUser>("User", userSchema);
export default User;
