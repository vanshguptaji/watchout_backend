import mongoose from 'mongoose';

export interface IContestParticipation {
    contestId: mongoose.Types.ObjectId;
    rank: number;
    score: number;
    contestProblems: {
        problemId: mongoose.Types.ObjectId;
        score: number;
        submissionTime: Date;
        submissionStatus: {
            type: String;
            enum: ["correct", "wrong", "partially correct"];
            default: "wrong";
        };
    }[];
}

export interface IContestModeration {
    contestId: mongoose.Types.ObjectId;
}
export interface IContestCreation {
    contestId: mongoose.Types.ObjectId;
}

export interface IFollowers {
    userId: mongoose.Types.ObjectId;
    followedAt: Date;
}

declare global {
  namespace Express {
    interface Request {
      user?: IUser;
    }
  }
}

export interface ISolvedProblem {
    problemId: mongoose.Types.ObjectId;
    solvedAt: Date;
}

export interface IProfile {
    name?: string;
    institution?: string;
    country?: string;
    avatarUrl?: string;
    bio?: string;
}

export interface IUserMethods {
    isPasswordCorrect(password: string): Promise<boolean>;
    generateAccessToken(): string;
    generateRefreshToken(): string;
}

export interface IUser extends mongoose.Document, IUserMethods {
    username: string;
    email: string;
    password: string;
    online: boolean;
    role: 'admin' | 'participant';
    profilePicture?: string; // Add this line for the profile picture field
    profile?: IProfile;
    followers: IFollowers[];
    following: IFollowers[];
    rating: number;
    contestsParticipated: Array<{
        contestId: mongoose.Types.ObjectId;
        rank?: number;
        score?: number;
        contestProblems: Array<{
            problemId: mongoose.Types.ObjectId;
            score: number;
            submissionTime: Date;
            submissionStatus: "correct" | "wrong" | "partially correct";
        }>;
    }>;
    contestsCreated: IContestCreation[];
    contestsModerated: IContestModeration[];
    solvedProblems: ISolvedProblem[];
    refreshToken?: string;
    createdAt: Date;
    updatedAt: Date;
}

export interface IServer {
  serverId: mongoose.Types.ObjectId;
  joinedAt: Date;
  nickname?: string;
  roles: string[];
}

export interface IDirectMessage {
  userId: mongoose.Types.ObjectId;
  unreadCount: number;
}

export interface IFriend {
  userId: mongoose.Types.ObjectId;
  status: 'pending' | 'accepted' | 'blocked';
  addedAt: Date;
}

export interface INotifications {
  mentions: boolean;
  directMessages: boolean;
  friendRequests: boolean;
  serverInvites: boolean;
}

export interface IUserMethods {
  isPasswordCorrect(password: string): Promise<boolean>;
  generateAccessToken(): string;
  generateRefreshToken(): string;
}

export interface IUser extends mongoose.Document, IUserMethods {
  username: string;
  email: string;
  password: string;
  displayName?: string;
  avatarUrl?: string;
  status: 'online' | 'idle' | 'dnd' | 'invisible' | 'offline';
  customStatus?: string;
  servers: IServer[];
  directMessages: IDirectMessage[];
  friends: IFriend[];
  notifications: INotifications;
  theme: 'dark' | 'light';
  refreshToken?: string;
  createdAt: Date;
  updatedAt: Date;
}
