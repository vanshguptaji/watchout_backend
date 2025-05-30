import mongoose from 'mongoose';

export interface IAttachment {
  url: string;
  type: 'image' | 'video' | 'audio' | 'file';
  name: string;
  size?: number;
}

export interface IMention {
  userId: mongoose.Types.ObjectId;
  username: string;
}

export interface IReaction {
  emoji: string;
  users: mongoose.Types.ObjectId[];
}

export interface IMessage extends mongoose.Document {
  content: string;
  sender: mongoose.Types.ObjectId;
  channelId?: mongoose.Types.ObjectId;
  serverId?: mongoose.Types.ObjectId;
  directMessageId?: string;
  attachments?: IAttachment[];
  mentions?: mongoose.Types.ObjectId[];
    reactions: {
    emoji: string;
    userId: mongoose.Types.ObjectId;
  }[];
  isEdited: boolean;
  isPinned: boolean;
  createdAt: Date;
  updatedAt: Date;
}
