import { Router } from "express";
import {
    createChannel,
    createInvite,
    createServer,
    deleteChannel,
    deleteServer,
    getServerDetails,
    getServerMembers,
    getUserServers,
    joinServer,
    kickMember,
    leaveServer,
    updateChannel,
    updateMemberRoles,
    updateServer
} from "../controllers/server.controllers";
import { verifyJWT } from "../middlewares/auth.middlewares.js";

const router = Router();

// Server management routes
router.route("/").post(verifyJWT, createServer);
router.route("/me").get(verifyJWT, getUserServers);
router.route("/:serverId").get(verifyJWT, getServerDetails);
router.route("/:serverId").patch(verifyJWT, updateServer);
router.route("/:serverId").delete(verifyJWT, deleteServer);

// Server membership routes
router.route("/:serverId/members").get(verifyJWT, getServerMembers);
router.route("/:serverId/join/:inviteCode").post(verifyJWT, joinServer);
router.route("/:serverId/leave").post(verifyJWT, leaveServer);
router.route("/:serverId/kick/:userId").post(verifyJWT, kickMember);
router.route("/:serverId/members/:userId/roles").patch(verifyJWT, updateMemberRoles);

// Channel management routes
router.route("/:serverId/channels").post(verifyJWT, createChannel);
router.route("/:serverId/channels/:channelId").patch(verifyJWT, updateChannel);
router.route("/:serverId/channels/:channelId").delete(verifyJWT, deleteChannel);

// Invite routes
router.route("/:serverId/invites").post(verifyJWT, createInvite);

export default router;