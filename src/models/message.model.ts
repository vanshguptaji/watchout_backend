import mongoose, { Model, Schema } from "mongoose";
import { IMessage } from "../types/message.types";

const messageSchema = new Schema<IMessage>(
  {
    content: {
      type: String,
      required: true
    },
    sender: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    channelId: {
      type: Schema.Types.ObjectId,
      ref: "Server.channels",
      required: function(this: IMessage) {
        return !this.directMessageId;
      }
    },
    serverId: {
      type: Schema.Types.ObjectId,
      ref: "Server",
      required: function(this: IMessage) {
        return !this.directMessageId;
      }
    },
    directMessageId: {
      type: String,
      required: function(this: IMessage) {
        return !this.channelId;
      }
    },
    attachments: [{
      url: { type: String, required: true },
      type: { type: String, enum: ["image", "video", "audio", "file"], required: true },
      name: { type: String, required: true },
      size: { type: Number }
    }],
    mentions: [{
      userId: { type: Schema.Types.ObjectId, ref: "User" },
      username: { type: String }
    }],
    reactions: [{
      emoji: { type: String, required: true },
      users: [{ type: Schema.Types.ObjectId, ref: "User" }]
    }],
    isEdited: {
      type: Boolean,
      default: false
    },
    isPinned: {
      type: Boolean,
      default: false
    }
  },
  { timestamps: true }
);

// Create compound indexes for efficient querying
messageSchema.index({ serverId: 1, channelId: 1, createdAt: -1 });
messageSchema.index({ directMessageId: 1, createdAt: -1 });

const Message: Model<IMessage> = mongoose.model<IMessage>("Message", messageSchema);
export default Message;