import mongoose, { Model, Schema } from "mongoose";
import { IServer } from "../types/server.types";

const serverSchema = new Schema<IServer>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      trim: true,
    },
    iconUrl: {
      type: String,
      default: "",
    },
    owner: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    members: [{
      userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
      roles: [{ type: String, default: "member" }],
      nickname: { type: String },
      joinedAt: { type: Date, default: Date.now }
    }],
    channels: [{
      name: { type: String, required: true },
      type: { type: String, enum: ["text", "voice"], default: "text" },
      topic: { type: String },
      position: { type: Number, default: 0 },
      isPrivate: { type: Boolean, default: false },
      allowedRoles: [{ type: String }],
      allowedUsers: [{ type: Schema.Types.ObjectId, ref: "User" }]
    }],
    roles: [{
      name: { type: String, required: true },
      color: { type: String, default: "#99AAB5" },
      permissions: [{ type: String }],
      position: { type: Number, default: 0 },
    }],
    inviteCodes: [{
      code: { type: String, required: true },
      createdBy: { type: Schema.Types.ObjectId, ref: "User" },
      expiresAt: { type: Date },
      maxUses: { type: Number },
      uses: { type: Number, default: 0 }
    }]
  },
  { timestamps: true }
);

const Server: Model<IServer> = mongoose.model<IServer>("Server", serverSchema);
export default Server;