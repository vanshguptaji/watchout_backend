import { Request, Response } from "express";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { IUser } from "../types/user.types";
import User from "../models/user.model";
import { generateAccessAndRefreshTokens } from "../utils/tools.js";
import jwt from "jsonwebtoken";
import { sendOtpEmail } from "../utils/sendMail.js";
import mongoose from "mongoose";
import { verifyGoogleToken, getGoogleUser } from "../utils/googleAuth.js";
import cloudinary from "../config/cloudinary";

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
      "-password -refreshToken -contestsCreated"
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
      "-password -refreshToken -contestsCreated"
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
    (req as any).user._id,
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

  const user = (await User.findById((req as any).user._id)) as IUser | null;
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

const getUserData = asyncHandler(async (req: Request, res: Response) => {
  const userId = (req as any).user._id;

  const user = await User.aggregate([
    { $match: { _id: userId } },
    // Preserve the original contestsParticipated array
    { $addFields: { userContestsParticipated: "$contestsParticipated" } },
    {
      $lookup: {
        from: "contests",
        localField: "contestsParticipated.contestId",
        foreignField: "_id",
        as: "contestsParticipated",
      },
    },
    // Merge user's score and rank into each contestParticipated object
    {
      $addFields: {
        contestsParticipated: {
          $map: {
            input: "$contestsParticipated",
            as: "contest",
            in: {
              $mergeObjects: [
                "$$contest",
                {
                  score: {
                    $let: {
                      vars: {
                        userContest: {
                          $arrayElemAt: [
                            {
                              $filter: {
                                input: "$userContestsParticipated",
                                as: "uc",
                                cond: {
                                  $eq: ["$$uc.contestId", "$$contest._id"],
                                },
                              },
                            },
                            0,
                          ],
                        },
                      },
                      in: "$$userContest.score",
                    },
                  },
                  rank: {
                    $let: {
                      vars: {
                        userContest: {
                          $arrayElemAt: [
                            {
                              $filter: {
                                input: "$userContestsParticipated",
                                as: "uc",
                                cond: {
                                  $eq: ["$$uc.contestId", "$$contest._id"],
                                },
                              },
                            },
                            0,
                          ],
                        },
                      },
                      in: "$$userContest.rank",
                    },
                  },
                  contestProblems: {
                    $let: {
                      vars: {
                        userContest: {
                          $arrayElemAt: [
                            {
                              $filter: {
                                input: "$userContestsParticipated",
                                as: "uc",
                                cond: {
                                  $eq: ["$$uc.contestId", "$$contest._id"],
                                },
                              },
                            },
                            0,
                          ],
                        },
                      },
                      in: "$$userContest.contestProblems",
                    },
                  },
                },
              ],
            },
          },
        },
      },
    },
    // Unwind contestsParticipated and contestProblems for lookup
    {
      $unwind: {
        path: "$contestsParticipated",
        preserveNullAndEmptyArrays: true,
      },
    },
    {
      $unwind: {
        path: "$contestsParticipated.contestProblems",
        preserveNullAndEmptyArrays: true,
      },
    },
    // Lookup problem details
    {
      $lookup: {
        from: "problems",
        localField: "contestsParticipated.contestProblems.problemId",
        foreignField: "_id",
        as: "contestsParticipated.contestProblems.problemDetails",
      },
    },
    // Flatten problemDetails array
    {
      $addFields: {
        "contestsParticipated.contestProblems.problemDetails": {
          $arrayElemAt: [
            "$contestsParticipated.contestProblems.problemDetails",
            0,
          ],
        },
      },
    },
    // Group back contestProblems
    {
      $group: {
        _id: {
          userId: "$_id",
          contestId: "$contestsParticipated._id",
        },
        doc: { $first: "$$ROOT" },
        contest: { $first: "$contestsParticipated" },
        contestProblems: { $push: "$contestsParticipated.contestProblems" },
      },
    },
    {
      $addFields: {
        "contest.contestProblems": "$contestProblems",
      },
    },
    // Group back contestsParticipated
    {
      $group: {
        _id: "$doc._id",
        doc: { $first: "$doc" },
        contestsParticipated: { $push: "$contest" },
      },
    },
    {
      $addFields: {
        "doc.contestsParticipated": "$contestsParticipated",
      },
    },
    {
      $replaceRoot: { newRoot: "$doc" },
    },
    {
      $project: {
        password: 0,
        refreshToken: 0,
        userContestsParticipated: 0, // Hide the helper field
      },
    },
  ]);

  if (!user || user.length === 0) {
    throw new ApiError(404, "User not found");
  }

  res
    .status(200)
    .json(new ApiResponse(200, user[0], "User data retrieved successfully"));
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
      profile: { avatarUrl: picture },
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

const followAndUnfollow = asyncHandler(async (req: Request, res: Response) => {
  //TODO:
  //1. we will get the user profile from the request body
  //2. identify the user in the database
  //3. identify the user we are now about to follow
  //4. update the followers list of the user we are about to follow
  //5. update the following list of the user we are following from
  //6. return the updated user profile

  const userId = (req as any).user._id;
  const userThatIsFollowing = await User.findById(userId);

  const { idOfWhomWeAreFollowing } = req.body;
  const userThatIsFollowed = await User.findById(idOfWhomWeAreFollowing);

  if (!userThatIsFollowing || !userThatIsFollowed) {
    throw new ApiError(404, "User not found");
  }

  // Check if the user is already following the target user
  const isFollowing = userThatIsFollowing.following.includes(
    idOfWhomWeAreFollowing
  );
  if (isFollowing) {
    // If already following, unfollow the user
    userThatIsFollowing.following = userThatIsFollowing.following.filter(
      (id: any) => id.toString() !== idOfWhomWeAreFollowing.toString()
    );
    userThatIsFollowed.followers = userThatIsFollowed.followers.filter(
      (id: any) => id.toString() !== userId.toString()
    );
  } else {
    // If not following, follow the user
    userThatIsFollowing.following.push(idOfWhomWeAreFollowing);
    userThatIsFollowed.followers.push(userId);
  }

  await userThatIsFollowing.save();
  await userThatIsFollowed.save();

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: userThatIsFollowing },
        isFollowing
          ? "Unfollowed user successfully"
          : "Followed user successfully"
      )
    );
});

const searchFriendByName = asyncHandler(async (req: Request, res: Response) => {
  const { username } = req.body;
  if (!username) {
    throw new ApiError(400, "Username is required for search");
  }

  const listOfUsers = await User.find({
    username: { $regex: username, $options: "i" },
  }).select("_id username profile profilePicture");

  res.status(200).json(new ApiResponse(200, listOfUsers, "Users found"));
});

const suggestedUsersToFollow = asyncHandler(
  async (req: Request, res: Response) => {
    const userId = (req as any).user._id;
    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(400, "Can't identify the user");
    }

    const followingIds = user.following.map((f: any) =>
      f.userId ? f.userId.toString() : f.toString()
    );
    followingIds.push(userId.toString());

    const suggestions = await User.find({
      _id: { $nin: followingIds },
    })
      .select("username profile profilePicture followers")
      .sort({ "followers.length": -1 })
      .limit(10);

    res
      .status(200)
      .json(new ApiResponse(200, suggestions, "Suggested users to follow"));
  }
);

const getProfileOfUser = asyncHandler(async (req: Request, res: Response) => {
  //TODO:
  //1. get the userId of the profile to be searching from the params
  //2. find the user in the database
  //3. check if the user is the same as the logged in user
  //4. if the user is the same as the logged in user, return the user profile
  //5. if the user is not the same as the logged in user, return the user profile without the refresh token and password
  const searchUserId = req.params.userId;
  const loggedInUserId = (req as any).user._id;
  const user = await User.findById(searchUserId).select(
    "-password -refreshToken"
  );

  if (!user) {
    throw new ApiError(404, "User not found");
  }
  const currentUser = await User.findById(loggedInUserId);
  if (!currentUser) {
    throw new ApiError(404, "User not found(unauthorized)");
  }
  const isSameUser = loggedInUserId.toString() === searchUserId.toString();
  if (isSameUser) {
    res
      .status(200)
      .json(new ApiResponse(200, user, "User profile retrieved successfully"));
    return;
  }
  const userWithoutSensitiveData = {
    ...user.toObject(),
    password: undefined,
    refreshToken: undefined,
  };
  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        userWithoutSensitiveData,
        "User profile retrieved successfully"
      )
    );
});

const getUserById = asyncHandler(async (req: Request, res: Response) => {
  const { userId } = req.params;
  
  if (!mongoose.isValidObjectId(userId)) {
    throw new ApiError(400, "Invalid User ID format");
  }
  
  const requesterId = req.user?._id as mongoose.Types.ObjectId;
  const requester = await User.findById(requesterId);
  
  if (!requester) {
    throw new ApiError(404, "Requester not found");
  }
  
  // Find the requested user with basic info
  const user = await User.findById(userId).select(
    "-password -refreshToken"
  );
  
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  
  // For admins and contest organizers, provide more detailed information
  // For regular users, provide limited information
  let userData;
  
  if (requester.role === "admin") {
    // Admin users get full profile info except sensitive data
    userData = {
      _id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      profilePicture: user.profilePicture,
      profile: user.profile,
      rating: user.rating,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      // Include participation data but filter out unnecessary details
      contestsParticipated: user.contestsParticipated?.map(contest => ({
        contestId: contest.contestId,
        rank: contest.rank,
        score: contest.score
      }))
    };
  } else {
    // Regular users see limited profile information
    userData = {
      _id: user._id,
      username: user.username,
      role: user.role,
      profilePicture: user.profilePicture,
      profile: {
        name: user.profile?.name,
        institution: user.profile?.institution,
        country: user.profile?.country,
        bio: user.profile?.bio
      },
      rating: user.rating,
      createdAt: user.createdAt
    };
  }
  
  res.status(200).json(
    new ApiResponse(
      200,
      userData,
      "User profile retrieved successfully"
    )
  );
});

export { 
  registerUser,
  loginUser, 
  verifyLoginOTP, 
  logoutUser, 
  refreshAccessToken, 
  changePassword, 
  forgetPassword, 
  verifyResetPasswordOTP, 
  updatePassword, 
  getUserData, 
  googleLogin,
  getUserById,
  followAndUnfollow,
  searchFriendByName,
  suggestedUsersToFollow,
  getProfileOfUser,
};