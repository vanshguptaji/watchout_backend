import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import User from "../models/user.model";
import { IUser } from "../types/user.types";
import { ApiError } from "../utils/ApiError";
import { ApiResponse } from "../utils/ApiResponse";
import { asyncHandler } from "../utils/asyncHandler";
import { getGoogleUser } from "../utils/googleAuth";
import { sendOtpEmail } from "../utils/sendMail";
import { generateAccessAndRefreshTokens } from "../utils/tools";

const otpStore = new Map<
  string,
  {
    user: {
      username: string;
      email: string;
      password: string;
      verified?: boolean;
    };
    otp: string;
    expiry: number;
    otpVerified?: boolean;
  }
>();

const registerUser = asyncHandler(async (req: Request, res: Response) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    throw new ApiError(
      400,
      "All fields (username, email, and password) are required."
    );
  }

  const existingUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existingUser) {
    throw new ApiError(
      409,
      "A user with this email or username already exists."
    );
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes

  otpStore.set(email, {
    user: { username, email, password },
    otp,
    expiry,
  });

  try {
    await sendOtpEmail(email, otp);
  } catch (error) {
    otpStore.delete(email);
    console.error("Error sending OTP email:", error);
    throw new ApiError(
      500,
      "Failed to send OTP email. Please try again later."
    );
  }

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        null,
        "OTP sent successfully. Please check your email."
      )
    );
});

const verifyLoginOTP = asyncHandler(async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    throw new ApiError(400, "Both email and OTP are required.");
  }

  const stored = otpStore.get(email);

  if (!stored) {
    throw new ApiError(
      400,
      "No OTP found for this email. Please request a new OTP."
    );
  }

  if (Date.now() > stored.expiry) {
    otpStore.delete(email);
    throw new ApiError(400, "The OTP has expired. Please request a new OTP.");
  }

  if (stored.otp !== otp) {
    throw new ApiError(401, "Invalid OTP. Please try again.");
  }

  const { username, password } = stored.user;

  try {
    const newUser = await User.create({ username, email, password });
    otpStore.delete(email);

    const user = await User.findById(newUser._id).select(
      "-password -refreshToken"
    );

    res
      .status(201)
      .json(new ApiResponse(201, user, "User registered successfully."));
  } catch (error) {
    console.error("Error creating user:", error);
    throw new ApiError(
      500,
      "An error occurred while registering the user. Please try again."
    );
  }
});

const loginUser = asyncHandler(async (req: Request, res: Response) => {
  const { email, password }: { email: string; password: string } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "Both email and password are required.");
  }

  const user = (await User.findOne({ email })) as IUser | null;

  if (!user) {
    throw new ApiError(404, "No user found with this email.");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Incorrect password. Please try again.");
  }

  try {
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id!.toString()
    );

    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    };

    res
      .cookie("accessToken", accessToken, cookieOptions)
      .cookie("refreshToken", refreshToken, cookieOptions)
      .json(
        new ApiResponse(
          200,
          { user: loggedInUser, accessToken, refreshToken },
          "User logged in successfully."
        )
      );
  } catch (error) {
    console.error("Error during login:", error);
    throw new ApiError(
      500,
      "An error occurred during login. Please try again."
    );
  }
});

const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  await User.findByIdAndUpdate(
    req.user?._id,
    { $set: { refreshToken: undefined } },
    { new: true }
  );

  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  };

  res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});

interface DecodedToken {
  _id: string;
  iat: number;
  exp: number;
}

const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized request");
  }
  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET!
    ) as DecodedToken;

    const user = (await User.findById(decodedToken._id)) as IUser | null;
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incomingRefreshToken !== user.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    };

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id!.toString());

    res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error: any) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

const changePassword = asyncHandler(async (req: Request, res: Response) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    throw new ApiError(400, "Old and new passwords are required");
  }

  const user = (await User.findById(req.user?._id)) as IUser | null;
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  const isPasswordValid = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordValid) {
    throw new ApiError(401, "Incorrect password");
  }

  user.password = newPassword;
  await user.save();

  res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

const forgetPassword = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, "Email is required.");
  }

  const user = (await User.findOne({ email })) as IUser | null;

  if (!user) {
    throw new ApiError(404, "No user found with this email.");
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes

  otpStore.set(email, {
    user: {
      username: user.username,
      email: user.email,
      password: user.password,
    },
    otp,
    expiry,
  });

  try {
    await sendOtpEmail(email, otp);
  } catch (error) {
    otpStore.delete(email);
    console.error("Error sending OTP email:", error);
    throw new ApiError(
      500,
      "Failed to send OTP email. Please try again later."
    );
  }

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        null,
        "OTP sent successfully. Please check your email."
      )
    );
});

const verifyResetPasswordOTP = asyncHandler(
  async (req: Request, res: Response) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
      throw new ApiError(400, "Email and OTP are required");
    }

    const stored = otpStore.get(email);

    if (!stored) {
      throw new ApiError(400, "No OTP found for this email");
    }

    if (Date.now() > stored.expiry) {
      otpStore.delete(email);
      throw new ApiError(400, "OTP expired");
    }

    if (stored.otp !== otp) {
      throw new ApiError(401, "Invalid OTP");
    }

    otpStore.set(email, { ...stored, otpVerified: true });

    res.status(200).json(new ApiResponse(200, {}, "OTP verified successfully"));
  }
);

const updatePassword = asyncHandler(async (req: Request, res: Response) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    throw new ApiError(400, "Email and new password are required");
  }

  const stored = otpStore.get(email);

  if (!stored || !stored.otpVerified) {
    throw new ApiError(
      400,
      "OTP verification is required before updating the password"
    );
  }

  const user = (await User.findOne({ email })) as IUser | null;
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  if (user.password === newPassword) {
    throw new ApiError(
      400,
      "New password cannot be the same as the old password"
    );
  }

  user.password = newPassword;
  await user.save();
  otpStore.delete(email);

  res
    .status(200)
    .json(new ApiResponse(200, {}, "Password updated successfully"));
});

const googleLogin = asyncHandler(async (req: Request, res: Response) => {
  const idToken = req.body.idToken;
  if (!idToken) {
    throw new ApiError(400, "ID token is required");
  }

  const googleUser = await getGoogleUser(idToken);

  if (!googleUser || !googleUser.email) {
    throw new ApiError(401, "Invalid Google ID token");
  }

  const { email, name, picture } = googleUser;

  let user = await User.findOne({ email });

  if (!user) {
    user = await User.create({
      username: name,
      email,
      avatarUrl: picture,
      password: "",
    });
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id!.toString()
  );

  const message =
    user.createdAt.getTime() === user.updatedAt.getTime()
      ? "User registered successfully"
      : "User logged in successfully";

  res
    .status(200)
    .json(new ApiResponse(200, { user, accessToken, refreshToken }, message));
});

// Get user's friends list
const getFriendsList = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?._id;
  
  const user = await User.findById(userId)
    .populate({
      path: 'friends.userId',
      select: 'username displayName avatarUrl status customStatus'
    });
  
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  // Sort friends by status (online first, then others)
  const friends = user.friends.sort((a, b) => {
    // @ts-ignore - The populated field has status
    const statusA = a.userId?.status || 'offline';
    // @ts-ignore - The populated field has status
    const statusB = b.userId?.status || 'offline';
    
    if (statusA === 'online' && statusB !== 'online') return -1;
    if (statusA !== 'online' && statusB === 'online') return 1;
    return 0;
  });
  
  res.status(200).json(
    new ApiResponse(200, { friends }, "Friends list retrieved successfully")
  );
});

// Send friend request
const sendFriendRequest = asyncHandler(async (req: Request, res: Response) => {
  const { targetUserId } = req.body;
  const userId = req.user?._id;
  
  if (!targetUserId) {
    throw new ApiError(400, "Target user ID or username is required");
  }

  if (userId?.toString() === targetUserId.toString()) {
    throw new ApiError(400, "You cannot send a friend request to yourself");
  }
  
  // Find the target user - first try by ID, then by username
  let targetUser;
  
  // Check if targetUserId is a valid ObjectId
  if (mongoose.Types.ObjectId.isValid(targetUserId)) {
    targetUser = await User.findById(targetUserId);
  }
  
  // If not found by ID or not a valid ObjectId, try by username
  if (!targetUser) {
    targetUser = await User.findOne({ 
      username: { $regex: `^${targetUserId}$`, $options: 'i' } 
    });
  }
  
  if (!targetUser) {
    throw new ApiError(404, "User not found");
  }
  
  // Prevent sending friend request to yourself (check again with found user)
  if (userId?.toString() === (targetUser._id as any).toString()) {
    throw new ApiError(400, "You cannot send a friend request to yourself");
  }
  
  // Find the requesting user
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  // Check if a friend relationship already exists
  const existingFriendship = user.friends.find(
    f => f.userId.toString() === targetUser._id.toString()
  );
  
  if (existingFriendship) {
    if (existingFriendship.status === 'blocked') {
      throw new ApiError(400, "You have blocked this user");
    }
    if (existingFriendship.status === 'accepted') {
      throw new ApiError(400, "This user is already your friend");
    }
    if (existingFriendship.status === 'pending') {
      throw new ApiError(400, "A friend request is already pending");
    }
  }
  
  // Check if target user has blocked the requesting user
  const targetUserBlocked = targetUser.friends.find(
    f => f.userId.toString() === userId?.toString() && f.status === 'blocked'
  );
  
  if (targetUserBlocked) {
    throw new ApiError(403, "Cannot send friend request");
  }
  
  // Add friend request for the requesting user
  user.friends.push({
    userId: targetUser._id as mongoose.Types.ObjectId,
    status: 'pending',
    addedAt: new Date()
  });
  await user.save();
  
  // Add pending request for the target user
  targetUser.friends.push({
    userId: userId as mongoose.Types.ObjectId,
    status: 'pending',
    addedAt: new Date()
  });
  await targetUser.save();
  
  res.status(200).json(
    new ApiResponse(200, {}, "Friend request sent successfully")
  );
});

// Respond to friend request (accept/reject)
const respondToFriendRequest = asyncHandler(async (req: Request, res: Response) => {
  const { requesterId, action } = req.body;
  const userId = req.user?._id as mongoose.Types.ObjectId;
  
  if (!requesterId || !action) {
    throw new ApiError(400, "Requester ID and action are required");
  }
  
  if (action !== 'accept' && action !== 'reject') {
    throw new ApiError(400, "Action must be either 'accept' or 'reject'");
  }
  
  // Find the current user
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  // Find the requesting user
  const requester = await User.findById(requesterId);
  if (!requester) {
    throw new ApiError(404, "Requesting user not found");
  }
  
  // Check if there's a pending request from the requester
  const requestIndex = user.friends.findIndex(
    f => f.userId.toString() === requesterId.toString() && f.status === 'pending'
  );
  
  if (requestIndex === -1) {
    throw new ApiError(404, "No pending friend request from this user");
  }
  
  // Find the matching request on the requester's side
  const requesterRequestIndex = requester.friends.findIndex(
    f => f.userId.toString() === userId.toString() && f.status === 'pending'
  );
  
  if (action === 'accept') {
    // Update both users' friend lists to 'accepted'
    user.friends[requestIndex].status = 'accepted';
    
    if (requesterRequestIndex !== -1) {
      requester.friends[requesterRequestIndex].status = 'accepted';
    } else {
      // Add the current user to requester's friends list if not present
      requester.friends.push({
        userId: userId,
        status: 'accepted',
        addedAt: new Date()
      });
    }
    
    await user.save();
    await requester.save();
    
    res.status(200).json(
      new ApiResponse(200, {}, "Friend request accepted")
    );
  } else {
    // Reject: Remove the request from both users
    user.friends.splice(requestIndex, 1);
    
    if (requesterRequestIndex !== -1) {
      requester.friends.splice(requesterRequestIndex, 1);
    }
    
    await user.save();
    await requester.save();
    
    res.status(200).json(
      new ApiResponse(200, {}, "Friend request rejected")
    );
  }
});

// Remove friend
const removeFriend = asyncHandler(async (req: Request, res: Response) => {
  const { friendId } = req.params;
  const userId = req.user?._id as mongoose.Types.ObjectId;
  
  // Find current user
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  // Find friend
  const friend = await User.findById(friendId);
  if (!friend) {
    throw new ApiError(404, "Friend not found");
  }
  
  // Check if they're friends
  const friendIndex = user.friends.findIndex(
    f => f.userId.toString() === friendId.toString() && f.status === 'accepted'
  );
  
  if (friendIndex === -1) {
    throw new ApiError(404, "This user is not your friend");
  }
  
  // Remove friend relationship from both users
  user.friends.splice(friendIndex, 1);
  
  const userFriendIndex = friend.friends.findIndex(
    f => f.userId.toString() === userId.toString() && f.status === 'accepted'
  );
  
  if (userFriendIndex !== -1) {
    friend.friends.splice(userFriendIndex, 1);
  }
  
  await user.save();
  await friend.save();
  
  res.status(200).json(
    new ApiResponse(200, {}, "Friend removed successfully")
  );
});

// Block user
const blockUser = asyncHandler(async (req: Request, res: Response) => {
  const { userId: targetUserId } = req.params;
  const userId = req.user?._id;
  
  if (userId?.toString() === targetUserId.toString()) {
    throw new ApiError(400, "You cannot block yourself");
  }
  
  // Find current user
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  // Find target user
  const targetUser = await User.findById(targetUserId);
  if (!targetUser) {
    throw new ApiError(404, "Target user not found");
  }
  
  // Check if already blocked
  const existingRelationship = user.friends.find(
    f => f.userId.toString() === targetUserId.toString()
  );
  
  if (existingRelationship) {
    if (existingRelationship.status === 'blocked') {
      throw new ApiError(400, "This user is already blocked");
    }
    // Update existing relationship to blocked
    existingRelationship.status = 'blocked';
  } else {
    // Create new blocked relationship
    user.friends.push({
      userId: new mongoose.Types.ObjectId(targetUserId),
      status: 'blocked',
      addedAt: new Date()
    });
  }
  
  // Remove any friend relationship from target user's side
  const targetUserRelationship = targetUser.friends.findIndex(
    f => f.userId.toString() === userId?.toString()
  );
  
  if (targetUserRelationship !== -1) {
    targetUser.friends.splice(targetUserRelationship, 1);
  }
  
  await user.save();
  await targetUser.save();
  
  res.status(200).json(
    new ApiResponse(200, {}, "User blocked successfully")
  );
});

// Unblock user
const unblockUser = asyncHandler(async (req: Request, res: Response) => {
  const { userId: targetUserId } = req.params;
  const userId = req.user?._id;
  
  // Find current user
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  // Check if the user is blocked
  const blockedIndex = user.friends.findIndex(
    f => f.userId.toString() === targetUserId.toString() && f.status === 'blocked'
  );
  
  if (blockedIndex === -1) {
    throw new ApiError(404, "This user is not blocked");
  }
  
  // Remove the blocked relationship
  user.friends.splice(blockedIndex, 1);
  await user.save();
  
  res.status(200).json(
    new ApiResponse(200, {}, "User unblocked successfully")
  );
});

// User profile and status updates
const getUserProfile = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?._id;
  
  const user = await User.findById(userId)
    .select('-password -refreshToken');
  
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  res.status(200).json(
    new ApiResponse(200, { user }, "User profile retrieved successfully")
  );
});

const updateUserStatus = asyncHandler(async (req: Request, res: Response) => {
  const { status, customStatus } = req.body;
  const userId = req.user?._id;
  
  // Validate status
  const validStatuses = ["online", "idle", "dnd", "invisible", "offline"];
  if (status && !validStatuses.includes(status)) {
    throw new ApiError(400, "Invalid status value");
  }
  
  // Validate custom status
  if (customStatus && customStatus.length > 128) {
    throw new ApiError(400, "Custom status should be 128 characters or less");
  }
  
  const updateData: Record<string, any> = {};
  if (status) updateData.status = status;
  if (customStatus !== undefined) updateData.customStatus = customStatus;
  
  const user = await User.findByIdAndUpdate(
    userId,
    { $set: updateData },
    { new: true }
  ).select('-password -refreshToken');
  
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  res.status(200).json(
    new ApiResponse(200, { user }, "Status updated successfully")
  );
});

const updateUserProfile = asyncHandler(async (req: Request, res: Response) => {
  const { displayName, avatarUrl, theme } = req.body;
  const userId = req.user?._id;
  
  const updateData: Record<string, any> = {};
  if (displayName !== undefined) updateData.displayName = displayName;
  if (avatarUrl !== undefined) updateData.avatarUrl = avatarUrl;
  if (theme !== undefined) {
    if (theme !== 'dark' && theme !== 'light') {
      throw new ApiError(400, "Theme must be 'dark' or 'light'");
    }
    updateData.theme = theme;
  }
  
  const user = await User.findByIdAndUpdate(
    userId,
    { $set: updateData },
    { new: true }
  ).select('-password -refreshToken');
  
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  res.status(200).json(
    new ApiResponse(200, { user }, "Profile updated successfully")
  );
});

// Search users by username or display name
const searchUsers = asyncHandler(async (req: Request, res: Response) => {
  const { query } = req.query;
  const currentUserId = req.user?._id;
  
  if (!query || typeof query !== 'string') {
    throw new ApiError(400, "Search query is required");
  }
  
  if (query.length < 2) {
    throw new ApiError(400, "Search query must be at least 2 characters");
  }
  
  try {
    // Search for users by username or display name (case-insensitive)
    const users = await User.find({
      $and: [
        { _id: { $ne: currentUserId } }, // Exclude current user
        {
          $or: [
            { username: { $regex: query, $options: 'i' } },
            { displayName: { $regex: query, $options: 'i' } }
          ]
        }
      ]
    })
    .select('username displayName avatarUrl status customStatus')
    .limit(20); // Limit results to prevent large responses
    
    res.status(200).json(
      new ApiResponse(200, { users }, "Users found successfully")
    );
  } catch (error) {
    console.error("Error searching users:", error);
    throw new ApiError(500, "Error searching users");
  }
});

export {
  blockUser,
  changePassword,
  forgetPassword,
  getFriendsList,
  getUserProfile,
  googleLogin,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  removeFriend,
  respondToFriendRequest,
  searchUsers, // Add this line
  sendFriendRequest,
  unblockUser,
  updatePassword,
  updateUserProfile,
  updateUserStatus,
  verifyLoginOTP,
  verifyResetPasswordOTP
};

