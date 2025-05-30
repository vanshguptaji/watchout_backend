import { Router } from "express";
import {
    addReaction,
    deleteMessage,
    editMessage,
    getChannelMessages,
    getDMMessages,
    getPinnedMessages,
    pinMessage,
    removeReaction,
    sendChannelMessage,
    sendDirectMessage,
    unpinMessage
} from "../controllers/message.controllers.js";
import { verifyJWT } from "../middlewares/auth.middlewares.js";

const router = Router();

// Server channel messages
router.route("/channels/:serverId/:channelId").get(verifyJWT, getChannelMessages);
router.route("/channels/:serverId/:channelId").post(verifyJWT, sendChannelMessage);

// Direct messages
router.route("/dm/:userId").get(verifyJWT, getDMMessages);
router.route("/dm/:userId").post(verifyJWT, sendDirectMessage);

// Message actions
router.route("/:messageId").patch(verifyJWT, editMessage);
router.route("/:messageId").delete(verifyJWT, deleteMessage);
router.route("/:messageId/react").post(verifyJWT, addReaction);
router.route("/:messageId/react/:emoji").delete(verifyJWT, removeReaction);
router.route("/:messageId/pin").post(verifyJWT, pinMessage);
router.route("/:messageId/unpin").post(verifyJWT, unpinMessage);

// Pinned messages
router.route("/pinned/channels/:serverId/:channelId").get(verifyJWT, getPinnedMessages);
router.route("/pinned/dm/:userId").get(verifyJWT, getPinnedMessages);

export default router;