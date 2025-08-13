import { Request, Response } from "express";
import mongoose from "mongoose";
import { io } from "../app";
import Message from "../models/message.model";
import Server from "../models/server.model";
import User from "../models/user.model";
import { ApiError } from "../utils/ApiError";
import { ApiResponse } from "../utils/ApiResponse";
import { asyncHandler } from "../utils/asyncHandler";

// Server channel messages
const getChannelMessages = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, channelId } = req.params;
  const userId = req.user?._id;
  const { cursor, limit = "50" } = req.query;
  
  // Validate server and channel existence
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }
  
  // Fix: Access _id instead of id on channel
  const channel = server.channels.find(c => (c as any)._id?.toString() === channelId);
  if (!channel) {
    throw new ApiError(404, "Channel not found");
  }
  
  // Check user membership in server
  const isMember = server.members.some(member => 
    member.userId.toString() === userId?.toString()
  );
  
  if (!isMember) {
    throw new ApiError(403, "You are not a member of this server");
  }
  
  // Build query
  let query: any = { 
    serverId: new mongoose.Types.ObjectId(serverId),
    channelId: new mongoose.Types.ObjectId(channelId)
  };
  
  if (cursor) {
    query._id = { $lt: new mongoose.Types.ObjectId(cursor as string) };
  }
  
  const messages = await Message.find(query)
    .sort({ createdAt: -1 })
    .limit(parseInt(limit as string))
    .populate("sender", "username displayName avatarUrl")
    .populate("mentions", "username displayName");
  
  res.status(200).json(
    new ApiResponse(200, messages, "Messages retrieved successfully")
  );
});

const sendChannelMessage = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, channelId } = req.params;
  const { content, mentions = [] } = req.body;
  const userId = req.user?._id;
  
  if (!content || content.trim() === "") {
    throw new ApiError(400, "Message content cannot be empty");
  }
  
  // Validate server and channel existence
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }
  
  // Fix: Access _id instead of id on channel
  const channel = server.channels.find(c => (c as any)._id.toString() === channelId);
  if (!channel) {
    throw new ApiError(404, "Channel not found");
  }
  
  // Check user membership in server
  const isMember = server.members.some(member => 
    member.userId.toString() === userId?.toString()
  );
  
  if (!isMember) {
    throw new ApiError(403, "You are not a member of this server");
  }
  
  // Create new message
  const message = await Message.create({
    content,
    sender: userId,
    serverId,
    channelId,
    mentions: mentions.length > 0 ? mentions : undefined
  });
  
  const populatedMessage = await Message.findById(message._id)
    .populate("sender", "username displayName avatarUrl")
    .populate("mentions", "username displayName");
  
  // Emit socket event for real-time updates
  io.to(`channel:${channelId}`).emit('newMessage', populatedMessage);
  
  // Notify mentioned users
  if (mentions && mentions.length > 0) {
    const mentionedUsers = await User.find({ _id: { $in: mentions } });
    mentionedUsers.forEach(user => {
      if (user.notifications?.mentions) {
        io.to(`user:${user._id}`).emit('mention', {
          message: populatedMessage,
          server: server.name,
          channel: channel.name
        });
      }
    });
  }
  
  res.status(201).json(
    new ApiResponse(201, populatedMessage, "Message sent successfully")
  );
});

// Direct messages
const getDMMessages = asyncHandler(async (req: Request, res: Response) => {
  const { userId: targetUserId } = req.params;
  const userId = req.user?._id;
  const { cursor, limit = "50" } = req.query;
  
  // Check if the target user exists
  const targetUser = await User.findById(targetUserId);
  if (!targetUser) {
    throw new ApiError(404, "User not found");
  }
  
  // Build query for messages between the two users
  let query: any = {
    serverId: null,
    channelId: null,
    $or: [
      { sender: userId, directMessageId: targetUserId },
      { sender: targetUserId, directMessageId: userId }
    ]
  };
  
  if (cursor) {
    query._id = { $lt: new mongoose.Types.ObjectId(cursor as string) };
  }
  
  const messages = await Message.find(query)
    .sort({ createdAt: -1 })
    .limit(parseInt(limit as string))
    .populate("sender", "username displayName avatarUrl");
  
  console.log(`Found ${messages.length} messages between ${userId} and ${targetUserId}`);
  
  // Reset unread count for the current user
  await User.findByIdAndUpdate(userId, {
    $set: {
      "directMessages.$[dm].unreadCount": 0
    }
  }, {
    arrayFilters: [{ "dm.userId": targetUserId }]
  });
  
  res.status(200).json(
    new ApiResponse(200, messages, "Direct messages retrieved successfully")
  );
});

const sendDirectMessage = asyncHandler(async (req: Request, res: Response) => {
  const { userId: recipientId } = req.params;
  const { content } = req.body;
  const userId = req.user?._id;
  
  if (!content || content.trim() === "") {
    throw new ApiError(400, "Message content cannot be empty");
  }
  
  // Check if recipient exists
  const recipient = await User.findById(recipientId);
  if (!recipient) {
    throw new ApiError(404, "Recipient user not found");
  }
  
  // Check if recipient has blocked sender
  const isBlocked = recipient.friends?.some(f => 
    f.userId.toString() === userId?.toString() && f.status === 'blocked'
  );
  
  if (isBlocked) {
    throw new ApiError(403, "You cannot send messages to this user");
  }
  
  // Create new direct message
  const message = await Message.create({
    content,
    sender: userId,
    directMessageId: recipientId
  });
  
  const populatedMessage = await Message.findById(message._id)
    .populate("sender", "username displayName avatarUrl");
  
  // Update or create DM relationship for both users
  const sender = await User.findById(userId);
  
  // For sender
  const senderDmExists = sender?.directMessages?.some(dm => 
    dm.userId.toString() === recipientId
  );
  
  if (!senderDmExists && sender) {
    sender.directMessages = sender.directMessages || [];
    sender.directMessages.push({
      userId: new mongoose.Types.ObjectId(recipientId),
      unreadCount: 0
    });
    await sender.save();
  }
  
  // For recipient
  const recipientDmExists = recipient.directMessages?.some(dm => 
    dm.userId.toString() === userId?.toString()
  );
  
  if (!recipientDmExists) {
    recipient.directMessages = recipient.directMessages || [];
    recipient.directMessages.push({
      userId: userId as mongoose.Types.ObjectId,
      unreadCount: 1
    });
    await recipient.save();
  } else {
    // Increment unread count
    await User.findByIdAndUpdate(recipientId, {
      $inc: {
        "directMessages.$[dm].unreadCount": 1
      }
    }, {
      arrayFilters: [{ "dm.userId": userId }]
    });
  }
  
  // Emit socket event for real-time updates to both users
  io.to(`user:${recipientId}`).emit('newDirectMessage', populatedMessage);
  io.to(`user:${userId}`).emit('newDirectMessage', populatedMessage);
  
  // Also emit to DM room if users are in the same room
  io.to(`dm:${recipientId}`).emit('newDirectMessage', populatedMessage);
  io.to(`dm:${userId}`).emit('newDirectMessage', populatedMessage);
  
  res.status(201).json(
    new ApiResponse(201, populatedMessage, "Direct message sent successfully")
  );
});

// Message actions
const editMessage = asyncHandler(async (req: Request, res: Response) => {
  const { messageId } = req.params;
  const { content } = req.body;
  const userId = req.user?._id;
  
  if (!content || content.trim() === "") {
    throw new ApiError(400, "Message content cannot be empty");
  }
  
  // Find message
  const message = await Message.findById(messageId);
  
  if (!message) {
    throw new ApiError(404, "Message not found");
  }
  
  // Check if user is the sender
  if (message.sender.toString() !== userId?.toString()) {
    throw new ApiError(403, "You can only edit your own messages");
  }
  
  // Update message
  message.content = content;
  message.isEdited = true;
  await message.save();
  
  const updatedMessage = await Message.findById(messageId)
    .populate("sender", "username displayName avatarUrl");
  
  // Emit socket event
  if (message.serverId && message.channelId) {
    io.to(`channel:${message.channelId}`).emit('messageUpdated', updatedMessage);
  } else if (message.directMessageId) {
    io.to(`user:${message.directMessageId}`).emit('messageUpdated', updatedMessage);
    io.to(`user:${message.sender}`).emit('messageUpdated', updatedMessage);
  }
  
  res.status(200).json(
    new ApiResponse(200, updatedMessage, "Message updated successfully")
  );
});

const deleteMessage = asyncHandler(async (req: Request, res: Response) => {
  const { messageId } = req.params;
  const userId = req.user?._id;
  
  // Find message
  const message = await Message.findById(messageId);
  
  if (!message) {
    throw new ApiError(404, "Message not found");
  }
  
  // Check if user is the sender
  if (message.sender.toString() !== userId?.toString()) {
    // Check if user has admin/moderator permissions in server
    if (message.serverId) {
      const server = await Server.findById(message.serverId);
      const userMember = server?.members.find(m => m.userId.toString() === userId?.toString());
      
      if (!userMember?.roles.some(role => ['owner', 'admin', 'moderator'].includes(role))) {
        throw new ApiError(403, "You don't have permission to delete this message");
      }
    } else {
      throw new ApiError(403, "You can only delete your own messages");
    }
  }
  
  // Store necessary info for socket event before deletion
  const { serverId, channelId, directMessageId, sender } = message;
  
  // Delete message
  await message.deleteOne();
  
  // Emit socket event
  if (serverId && channelId) {
    io.to(`channel:${channelId}`).emit('messageDeleted', { 
      messageId, channelId, serverId 
    });
  } else if (directMessageId) {
    io.to(`user:${directMessageId}`).emit('messageDeleted', { messageId });
    io.to(`user:${sender}`).emit('messageDeleted', { messageId });
  }
  
  res.status(200).json(
    new ApiResponse(200, { messageId }, "Message deleted successfully")
  );
});

const addReaction = asyncHandler(async (req: Request, res: Response) => {
  const { messageId } = req.params;
  const { emoji } = req.body;
  const userId = req.user?._id;
  
  if (!emoji) {
    throw new ApiError(400, "Emoji is required");
  }
  
  // Find message
  const message = await Message.findById(messageId);
  
  if (!message) {
    throw new ApiError(404, "Message not found");
  }
  
  // Check if user can access the message
  if (message.serverId) {
    const server = await Server.findById(message.serverId);
    const isMember = server?.members.some(m => m.userId.toString() === userId?.toString());
    
    if (!isMember) {
      throw new ApiError(403, "You don't have access to this message");
    }
  } else if (message.directMessageId && 
             message.directMessageId.toString() !== userId?.toString() && 
             message.sender.toString() !== userId?.toString()) {
    throw new ApiError(403, "You don't have access to this message");
  }
  
  // Add reaction if not already added
  const existingReaction = message.reactions.find(
    r => r.emoji === emoji && r.userId.toString() === userId?.toString()
  );
  
  if (!existingReaction) {
    message.reactions.push({
      emoji,
      userId: userId as mongoose.Types.ObjectId
    });
    await message.save();
  }
  
  const updatedMessage = await Message.findById(messageId)
    .populate("sender", "username displayName avatarUrl")
    .populate("reactions.userId", "username displayName");
  
  // Emit socket event
  if (message.serverId && message.channelId) {
    io.to(`channel:${message.channelId}`).emit('messageReaction', updatedMessage);
  } else if (message.directMessageId) {
    io.to(`user:${message.directMessageId}`).emit('messageReaction', updatedMessage);
    io.to(`user:${message.sender}`).emit('messageReaction', updatedMessage);
  }
  
  res.status(200).json(
    new ApiResponse(200, updatedMessage, "Reaction added successfully")
  );
});

const removeReaction = asyncHandler(async (req: Request, res: Response) => {
  const { messageId, emoji } = req.params;
  const userId = req.user?._id;
  
  // Find message
  const message = await Message.findById(messageId);
  
  if (!message) {
    throw new ApiError(404, "Message not found");
  }
  
  // Remove reaction
  message.reactions = message.reactions.filter(
    r => !(r.emoji === emoji && r.userId.toString() === userId?.toString())
  );
  
  await message.save();
  
  const updatedMessage = await Message.findById(messageId)
    .populate("sender", "username displayName avatarUrl")
    .populate("reactions.userId", "username displayName");
  
  // Emit socket event
  if (message.serverId && message.channelId) {
    io.to(`channel:${message.channelId}`).emit('messageReaction', updatedMessage);
  } else if (message.directMessageId) {
    io.to(`user:${message.directMessageId}`).emit('messageReaction', updatedMessage);
    io.to(`user:${message.sender}`).emit('messageReaction', updatedMessage);
  }
  
  res.status(200).json(
    new ApiResponse(200, updatedMessage, "Reaction removed successfully")
  );
});

const pinMessage = asyncHandler(async (req: Request, res: Response) => {
  const { messageId } = req.params;
  const userId = req.user?._id;
  
  // Find message
  const message = await Message.findById(messageId);
  
  if (!message) {
    throw new ApiError(404, "Message not found");
  }
  
  // Check permissions
  if (message.serverId) {
    const server = await Server.findById(message.serverId);
    const userMember = server?.members.find(m => m.userId.toString() === userId?.toString());
    
    if (!userMember?.roles.some(role => ['owner', 'admin', 'moderator'].includes(role))) {
      throw new ApiError(403, "You don't have permission to pin messages");
    }
  } else if (message.sender.toString() !== userId?.toString() && 
             message.directMessageId?.toString() !== userId?.toString()) {
    throw new ApiError(403, "You don't have permission to pin this message");
  }
  
  // Pin message
  message.isPinned = true;
  await message.save();
  
  const pinnedMessage = await Message.findById(messageId)
    .populate("sender", "username displayName avatarUrl");
  
  // Emit socket event
  if (message.serverId && message.channelId) {
    io.to(`channel:${message.channelId}`).emit('messagePinned', pinnedMessage);
  } else if (message.directMessageId) {
    io.to(`user:${message.directMessageId}`).emit('messagePinned', pinnedMessage);
    io.to(`user:${message.sender}`).emit('messagePinned', pinnedMessage);
  }
  
  res.status(200).json(
    new ApiResponse(200, pinnedMessage, "Message pinned successfully")
  );
});

const unpinMessage = asyncHandler(async (req: Request, res: Response) => {
  const { messageId } = req.params;
  const userId = req.user?._id;
  
  // Find message
  const message = await Message.findById(messageId);
  
  if (!message) {
    throw new ApiError(404, "Message not found");
  }
  
  if (!message.isPinned) {
    throw new ApiError(400, "Message is not pinned");
  }
  
  // Check permissions
  if (message.serverId) {
    const server = await Server.findById(message.serverId);
    const userMember = server?.members.find(m => m.userId.toString() === userId?.toString());
    
    if (!userMember?.roles.some(role => ['owner', 'admin', 'moderator'].includes(role))) {
      throw new ApiError(403, "You don't have permission to unpin messages");
    }
  } else if (message.sender.toString() !== userId?.toString() && 
             message.directMessageId?.toString() !== userId?.toString()) {
    throw new ApiError(403, "You don't have permission to unpin this message");
  }
  
  // Unpin message
  message.isPinned = false;
  await message.save();
  
  const unpinnedMessage = await Message.findById(messageId)
    .populate("sender", "username displayName avatarUrl");
  
  // Emit socket event
  if (message.serverId && message.channelId) {
    io.to(`channel:${message.channelId}`).emit('messageUnpinned', unpinnedMessage);
  } else if (message.directMessageId) {
    io.to(`user:${message.directMessageId}`).emit('messageUnpinned', unpinnedMessage);
    io.to(`user:${message.sender}`).emit('messageUnpinned', unpinnedMessage);
  }
  
  res.status(200).json(
    new ApiResponse(200, unpinnedMessage, "Message unpinned successfully")
  );
});

const getPinnedMessages = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, channelId, userId: targetUserId } = req.params;
  const userId = req.user?._id;
  
  let query: any = { isPinned: true };
  
  if (serverId && channelId) {
    // Get pinned messages from a server channel
    query.serverId = new mongoose.Types.ObjectId(serverId);
    query.channelId = new mongoose.Types.ObjectId(channelId);
    
    // Verify server access
    const server = await Server.findById(serverId);
    if (!server) {
      throw new ApiError(404, "Server not found");
    }
    
    const isMember = server.members.some(m => m.userId.toString() === userId?.toString());
    if (!isMember) {
      throw new ApiError(403, "You are not a member of this server");
    }
  } else if (targetUserId) {
    // Get pinned messages from DMs
    query.$or = [
      { sender: userId, directMessageId: targetUserId },
      { sender: targetUserId, directMessageId: userId }
    ];
  } else {
    throw new ApiError(400, "Invalid request parameters");
  }
  
  const pinnedMessages = await Message.find(query)
    .sort({ createdAt: -1 })
    .populate("sender", "username displayName avatarUrl");
  
  res.status(200).json(
    new ApiResponse(200, pinnedMessages, "Pinned messages retrieved successfully")
  );
});

export {
  addReaction, deleteMessage, editMessage, getChannelMessages, getDMMessages, getPinnedMessages, pinMessage, removeReaction, sendChannelMessage, sendDirectMessage, unpinMessage
};

