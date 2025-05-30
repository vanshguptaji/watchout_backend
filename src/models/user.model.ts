import bcrypt from "bcrypt";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import mongoose, { Model, Schema } from "mongoose";
import { IUser } from "../types/user.types";
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
      required: true,
    },
    displayName: {
      type: String,
      trim: true,
    },
    avatarUrl: {
      type: String,
      default: "", // Default avatar URL can be set here
    },
    status: {
      type: String,
      enum: ["online", "idle", "dnd", "invisible", "offline"],
      default: "offline",
    },
    customStatus: {
      type: String,
      maxlength: 128,
    },
    servers: [
      {
        serverId: { type: Schema.Types.ObjectId, ref: "Server" },
        joinedAt: { type: Date, default: Date.now },
        nickname: { type: String },
        roles: [{ type: String }],
      },
    ],
    directMessages: [
      {
        userId: { type: Schema.Types.ObjectId, ref: "User" },
        unreadCount: { type: Number, default: 0 },
      },
    ],
    friends: [
      {
        userId: { type: Schema.Types.ObjectId, ref: "User" },
        status: {
          type: String,
          enum: ["pending", "accepted", "blocked"],
          default: "pending",
        },
        addedAt: { type: Date, default: Date.now },
      },
    ],
    notifications: {
      mentions: { type: Boolean, default: true },
      directMessages: { type: Boolean, default: true },
      friendRequests: { type: Boolean, default: true },
      serverInvites: { type: Boolean, default: true },
    },
    theme: {
      type: String,
      enum: ["dark", "light"],
      default: "dark",
    },
    refreshToken: {
      type: String,
    },
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
  delete obj.password;
  delete obj.refreshToken;
  return obj;
};

userSchema.methods.isPasswordCorrect = async function (
  password: string
): Promise<boolean> {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function (): string {
  const secret = process.env.ACCESS_TOKEN_SECRET;
  if (!secret) {
    throw new Error("ACCESS_TOKEN_SECRET is not defined");
  }

  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      role: this.role,
    },
    secret,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "1d",
      algorithm: "HS256",
    } as jwt.SignOptions
  );
};

userSchema.methods.generateRefreshToken = function (): string {
  const secret = process.env.REFRESH_TOKEN_SECRET;
  if (!secret) {
    throw new Error("REFRESH_TOKEN_SECRET is not defined");
  }

  return jwt.sign(
    {
      _id: this._id,
    },
    secret,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY || "30d",
      algorithm: "HS256",
    } as jwt.SignOptions
  );
};

const User: Model<IUser> = mongoose.model<IUser>("User", userSchema);
export default User;
