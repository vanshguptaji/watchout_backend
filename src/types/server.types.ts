import mongoose from 'mongoose';

export interface IMember {
  userId: mongoose.Types.ObjectId;
  roles: string[];
  nickname?: string;
  joinedAt: Date;
}

export interface IChannel {
  name: string;
  type: 'text' | 'voice';
  topic?: string;
  position: number;
  isPrivate: boolean;
  allowedRoles?: string[];
  allowedUsers?: mongoose.Types.ObjectId[];
}

export interface IRole {
  name: string;
  color: string;
  permissions: string[];
  position: number;
}

export interface IInviteCode {
  code: string;
  createdBy: mongoose.Types.ObjectId;
  expiresAt?: Date;
  maxUses?: number;
  uses: number;
}

export interface IServer extends mongoose.Document {
  name: string;
  description?: string;
  iconUrl?: string;
  owner: mongoose.Types.ObjectId;
  members: IMember[];
  channels: IChannel[];
  roles: IRole[];
  inviteCodes: IInviteCode[];
  createdAt: Date;
  updatedAt: Date;
}