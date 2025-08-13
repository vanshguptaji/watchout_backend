import { Router } from "express";
import {
  blockUser,
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
  searchUsers,
  sendFriendRequest,
  unblockUser,
  updatePassword,
  updateUserProfile,
  updateUserStatus,
  verifyLoginOTP,
  verifyResetPasswordOTP,
} from "../controllers/user.controllers";
import { verifyJWT } from "../middlewares/auth.middlewares";

const router = Router();

// Auth routes
router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/v").post(verifyLoginOTP);
router.route("/forgot-password").post(forgetPassword);
router.route("/verify-reset-password-otp").post(verifyResetPasswordOTP);
router.route("/update-password").post(updatePassword);
router.route("/google").post(googleLogin);
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/refresh-token").post(refreshAccessToken);

// User profile routes
router.route("/me").get(verifyJWT, getUserProfile);
router.route("/status").patch(verifyJWT, updateUserStatus);
router.route("/profile").patch(verifyJWT, updateUserProfile);

// Friend management routes
router.route("/friends").get(verifyJWT, getFriendsList);
router.route("/friends/request").post(verifyJWT, sendFriendRequest);
router.route("/friends/respond").post(verifyJWT, respondToFriendRequest);
router.route("/friends/:friendId").delete(verifyJWT, removeFriend);
router.route("/friends/block/:userId").post(verifyJWT, blockUser);
router.route("/friends/unblock/:userId").post(verifyJWT, unblockUser);
router.route("/search").get(verifyJWT, searchUsers);

export default router;
