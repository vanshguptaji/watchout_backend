import { Request, Response } from "express";
import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";
import Server from "../models/server.model";
import User from "../models/user.model";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

// Create a new server
const createServer = asyncHandler(async (req: Request, res: Response) => {
  const { name, description, iconUrl } = req.body;
  const userId = req.user?._id;

  if (!name) {
    throw new ApiError(400, "Server name is required");
  }

  // Create server with default roles and channels
  const serverData = {
    name,
    description: description || "",
    iconUrl: iconUrl || "",
    owner: userId,
    members: [
      {
        userId,
        roles: ["owner"],
        joinedAt: new Date()
      }
    ],
    channels: [
      {
        name: "general",
        type: "text",
        topic: "General discussion",
        position: 0,
        isPrivate: false
      },
      {
        name: "voice-chat",
        type: "voice",
        topic: "Voice chat",
        position: 1,
        isPrivate: false
      }
    ],
    roles: [
      {
        name: "Owner",
        color: "#FFA500", // Orange
        permissions: ["admin", "manage_channels", "manage_roles", "kick_members", "ban_members", "manage_messages", "manage_server"],
        position: 2
      },
      {
        name: "Moderator",
        color: "#4CAF50", // Green
        permissions: ["manage_messages", "kick_members", "ban_members"],
        position: 1
      },
      {
        name: "@everyone",
        color: "#99AAB5", // Discord default role color
        permissions: ["read_messages", "send_messages", "embed_links", "attach_files", "add_reactions", "connect", "speak"],
        position: 0
      }
    ],
    inviteCodes: [
      {
        code: uuidv4().substring(0, 8),
        createdBy: userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 1 week expiration
        maxUses: 100,
        uses: 0
      }
    ]
  };

  const server = await Server.create(serverData);

  // Add server to user's servers
  await User.findByIdAndUpdate(
    userId,
    {
      $push: {
        servers: {
          serverId: server._id,
          joinedAt: new Date(),
          roles: ["owner"]
        }
      }
    }
  );

  res.status(201).json(
    new ApiResponse(201, { server }, "Server created successfully")
  );
});

// Get server details
const getServerDetails = asyncHandler(async (req: Request, res: Response) => {
  const { serverId } = req.params;
  const userId = req.user?._id;

  if (!userId) {
    throw new ApiError(401, "User not authenticated");
  }

  // Check if server exists and user is a member
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user is a member of this server
  const isMember = server.members.some(member => 
    member.userId.toString() === userId.toString()
  );

  if (!isMember) {
    throw new ApiError(403, "You are not a member of this server");
  }

  // Find the user's roles in this server
  const userMember = server.members.find(member => 
    member.userId.toString() === userId.toString()
  );

  // Sort channels by position
  const sortedChannels = [...server.channels].sort((a, b) => a.position - b.position);

  const response = {
    _id: server._id,
    name: server.name,
    description: server.description,
    iconUrl: server.iconUrl,
    owner: server.owner,
    channels: sortedChannels,
    roles: server.roles,
    userRoles: userMember?.roles || [],
    memberCount: server.members.length
  };

  res.status(200).json(
    new ApiResponse(200, { server: response }, "Server details retrieved successfully")
  );
});

// Get all servers the user is a member of
const getUserServers = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?._id;

  if (!userId) {
    throw new ApiError(401, "User not authenticated");
  }

  const user = await User.findById(userId).select("servers");
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  const serverIds = user.servers.map(s => s.serverId);

  // Fetch basic info about each server
  const servers = await Server.find(
    { _id: { $in: serverIds } },
    { 
      name: 1,
      iconUrl: 1,
      owner: 1,
      "members.userId": 1,
      "channels": { $slice: 5 } // Get first 5 channels for preview
    }
  );

  // Add user roles to each server
  const serversWithRoles = servers.map(server => {
    const userServer = user.servers.find(s => 
      s.serverId.toString() === (server._id as any).toString()
    );
    
    return {
      _id: server._id,
      name: server.name,
      iconUrl: server.iconUrl,
      isOwner: server.owner.toString() === userId.toString(),
      memberCount: server.members.length,
      channels: server.channels.filter(channel => !channel.isPrivate),
      roles: userServer?.roles || []
    };
  });

  res.status(200).json(
    new ApiResponse(200, { servers: serversWithRoles }, "User servers retrieved successfully")
  );
});

// Update server details
const updateServer = asyncHandler(async (req: Request, res: Response) => {
  const { serverId } = req.params;
  const { name, description, iconUrl } = req.body;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user is the owner
  if (server.owner.toString() !== (userId as any).toString()) {
    throw new ApiError(403, "Only the server owner can update server details");
  }

  // Update fields if provided
  const updateData: Record<string, any> = {};
  if (name) updateData.name = name;
  if (description !== undefined) updateData.description = description;
  if (iconUrl !== undefined) updateData.iconUrl = iconUrl;

  const updatedServer = await Server.findByIdAndUpdate(
    serverId,
    { $set: updateData },
    { new: true }
  );

  res.status(200).json(
    new ApiResponse(200, { server: updatedServer }, "Server updated successfully")
  );
});

// Delete server
const deleteServer = asyncHandler(async (req: Request, res: Response) => {
  const { serverId } = req.params;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user is the owner
  if (server.owner.toString() !== (userId as any).toString()) {
    throw new ApiError(403, "Only the server owner can delete the server");
  }

  // Get all member IDs
  const memberIds = server.members.map(member => member.userId);

  // Remove server from all members' server lists
  await User.updateMany(
    { _id: { $in: memberIds } },
    { $pull: { servers: { serverId: serverId } } }
  );

  // Delete the server
  await Server.findByIdAndDelete(serverId);

  // Delete all messages for this server
  // await Message.deleteMany({ serverId: serverId });

  res.status(200).json(
    new ApiResponse(200, {}, "Server deleted successfully")
  );
});

// Get server members
const getServerMembers = asyncHandler(async (req: Request, res: Response) => {
  const { serverId } = req.params;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user is a member
  const isMember = server.members.some(member => 
    member.userId.toString() === (userId as any).toString()
  );

  if (!isMember) {
    throw new ApiError(403, "You are not a member of this server");
  }

  // Get member details
  const memberIds = server.members.map(member => member.userId);
  
  const members = await User.find(
    { _id: { $in: memberIds } },
    {
      _id: 1,
      username: 1,
      displayName: 1,
      avatarUrl: 1,
      status: 1,
      customStatus: 1
    }
  );

  // Combine with server-specific roles
  const membersWithRoles = members.map(member => {
    const serverMember = server.members.find(m => 
      m.userId.toString() === member._id?.toString()
    );
    
    return {
      ...member.toObject(),
      roles: serverMember?.roles || [],
      nickname: serverMember?.nickname,
      joinedAt: serverMember?.joinedAt
    };
  });

  res.status(200).json(
    new ApiResponse(200, { members: membersWithRoles }, "Server members retrieved successfully")
  );
});

// Join server using invite code
const joinServer = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, inviteCode } = req.params;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user is already a member
  const isMember = server.members.some(member => 
    member.userId.toString() === (userId as any).toString()
  );

  if (isMember) {
    throw new ApiError(400, "You are already a member of this server");
  }

  // Check if invite code is valid
  const invite = server.inviteCodes.find(inv => inv.code === inviteCode);
  
  if (!invite) {
    throw new ApiError(404, "Invalid invite code");
  }

  if (invite.expiresAt && invite.expiresAt < new Date()) {
    throw new ApiError(400, "Invite code has expired");
  }

  if (invite.maxUses && invite.uses >= invite.maxUses) {
    throw new ApiError(400, "Invite code has reached maximum uses");
  }

  // Add user to server members
  server.members.push({
    userId: userId as unknown as mongoose.Types.ObjectId,
    roles: ["@everyone"],
    joinedAt: new Date()
  });

  // Increment invite code uses
  invite.uses += 1;
  await server.save();

  // Add server to user's server list
  await User.findByIdAndUpdate(
    userId,
    {
      $push: {
        servers: {
          serverId: server._id,
          joinedAt: new Date(),
          roles: ["@everyone"]
        }
      }
    }
  );

  res.status(200).json(
    new ApiResponse(200, {}, "Joined server successfully")
  );
});

// Leave server
const leaveServer = asyncHandler(async (req: Request, res: Response) => {
  const { serverId } = req.params;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user is a member
  const isMember = server.members.some(member => 
    member.userId.toString() === (userId as any).toString()
  );

  if (!isMember) {
    throw new ApiError(400, "You are not a member of this server");
  }

  // Check if user is the owner
  if (server.owner.toString() === (userId as any).toString()) {
    throw new ApiError(400, "Server owner cannot leave. Transfer ownership or delete the server instead.");
  }

  // Remove user from server members
  server.members = server.members.filter(member => 
    member.userId.toString() !== (userId as any).toString()
  );
  await server.save();

  // Remove server from user's server list
  await User.findByIdAndUpdate(
    userId,
    { $pull: { servers: { serverId: serverId } } }
  );

  res.status(200).json(
    new ApiResponse(200, {}, "Left server successfully")
  );
});

// Create a new server channel
const createChannel = asyncHandler(async (req: Request, res: Response) => {
  const { serverId } = req.params;
  const { name, type, topic, isPrivate, allowedRoles, allowedUsers } = req.body;
  const userId = req.user?._id;

  if (!name) {
    throw new ApiError(400, "Channel name is required");
  }

  // Validate channel type
  if (type && type !== 'text' && type !== 'voice') {
    throw new ApiError(400, "Channel type must be 'text' or 'voice'");
  }

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user has permission to create channels
  const member = server.members.find(m => m.userId.toString() === (userId as any).toString());
  if (!member) {
    throw new ApiError(403, "You are not a member of this server");
  }

  const userRoles = member.roles;
  
  // Check if user is owner or has manage_channels permission
  const isOwner = server.owner.toString() === (userId as any).toString();
  const hasPermission = isOwner || server.roles.some(role => 
    userRoles.includes(role.name) && role.permissions.includes('manage_channels')
  );

  if (!hasPermission) {
    throw new ApiError(403, "You don't have permission to create channels");
  }

  // Find the highest position to place the new channel
  const highestPosition = server.channels.length > 0 
    ? Math.max(...server.channels.map(c => c.position)) 
    : -1;

  // Create new channel
  const newChannel = {
    name,
    type: type || 'text',
    topic: topic || '',
    position: highestPosition + 1,
    isPrivate: isPrivate || false,
    allowedRoles: allowedRoles || [],
    allowedUsers: allowedUsers || []
  };

  server.channels.push(newChannel);
  await server.save();

  res.status(201).json(
    new ApiResponse(201, { channel: newChannel }, "Channel created successfully")
  );
});

// Update a channel
const updateChannel = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, channelId } = req.params;
  const { name, topic, position, isPrivate, allowedRoles, allowedUsers } = req.body;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user has permission
  const member = server.members.find(m => m.userId.toString() === (userId as any).toString());
  if (!member) {
    throw new ApiError(403, "You are not a member of this server");
  }

  const isOwner = server.owner.toString() === (userId as any).toString();
  const userRoles = member.roles;
  const hasPermission = isOwner || server.roles.some(role => 
    userRoles.includes(role.name) && role.permissions.includes('manage_channels')
  );

  if (!hasPermission) {
    throw new ApiError(403, "You don't have permission to update channels");
  }

  // Find the channel
  const channelIndex = server.channels.findIndex(c => (c as any)._id.toString() === channelId);
  if (channelIndex === -1) {
    throw new ApiError(404, "Channel not found");
  }

  // Update channel fields
  const channel = server.channels[channelIndex];
  if (name) channel.name = name;
  if (topic !== undefined) channel.topic = topic;
  if (position !== undefined) channel.position = position;
  if (isPrivate !== undefined) channel.isPrivate = isPrivate;
  if (allowedRoles) channel.allowedRoles = allowedRoles;
  if (allowedUsers) channel.allowedUsers = allowedUsers;

  await server.save();

  res.status(200).json(
    new ApiResponse(200, { channel }, "Channel updated successfully")
  );
});

// Delete a channel
const deleteChannel = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, channelId } = req.params;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user has permission
  const member = server.members.find(m => m.userId.toString() === (userId as any).toString());
  if (!member) {
    throw new ApiError(403, "You are not a member of this server");
  }

  const isOwner = server.owner.toString() === (userId as any).toString();
  const userRoles = member.roles;
  const hasPermission = isOwner || server.roles.some(role => 
    userRoles.includes(role.name) && role.permissions.includes('manage_channels')
  );

  if (!hasPermission) {
    throw new ApiError(403, "You don't have permission to delete channels");
  }

  // Find the channel
  const channelIndex = server.channels.findIndex(c => (c as any)._id.toString() === channelId);
  if (channelIndex === -1) {
    throw new ApiError(404, "Channel not found");
  }

  // Remove channel
  server.channels.splice(channelIndex, 1);
  await server.save();

  // Delete all messages in this channel
  // await Message.deleteMany({ channelId, serverId });

  res.status(200).json(
    new ApiResponse(200, {}, "Channel deleted successfully")
  );
});

// Create an invite code
const createInvite = asyncHandler(async (req: Request, res: Response) => {
  const { serverId } = req.params;
  const { expiresIn, maxUses } = req.body;
  const userId = req.user?._id;

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if user has permission
  const member = server.members.find(m => m.userId.toString() === (userId as any).toString());
  if (!member) {
    throw new ApiError(403, "You are not a member of this server");
  }

  const isOwner = server.owner.toString() === (userId as any).toString();
  const userRoles = member.roles;
  const hasPermission = isOwner || userRoles.includes('admin') || server.roles.some(role => 
    userRoles.includes(role.name) && 
    (role.permissions.includes('manage_server') || role.permissions.includes('create_invite'))
  );

  if (!hasPermission) {
    throw new ApiError(403, "You don't have permission to create invites");
  }

  // Generate a new invite code
  const code = uuidv4().substring(0, 8);
  
  // Calculate expiration date if provided
  let expiresAt: Date | undefined = undefined;
  if (expiresIn) {
    // expiresIn is in hours
    expiresAt = new Date(Date.now() + expiresIn * 60 * 60 * 1000);
  }

  const invite = {
    code,
    createdBy: userId as mongoose.Types.ObjectId,
    expiresAt,
    maxUses: maxUses || undefined,
    uses: 0
  };

  server.inviteCodes.push(invite);
  await server.save();

  res.status(201).json(
    new ApiResponse(201, { invite }, "Invite created successfully")
  );
});

// Update a member's roles
const updateMemberRoles = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, userId: targetUserId } = req.params;
  const { roles } = req.body;
  const userId = req.user?._id;

  if (!roles || !Array.isArray(roles)) {
    throw new ApiError(400, "Roles must be provided as an array");
  }

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if current user has permission
  const member = server.members.find(m => m.userId.toString() === (userId as any).toString());
  if (!member) {
    throw new ApiError(403, "You are not a member of this server");
  }

  const isOwner = server.owner.toString() === (userId as any).toString();
  const userRoles = member.roles;
  const hasPermission = isOwner || userRoles.includes('admin') || server.roles.some(role => 
    userRoles.includes(role.name) && role.permissions.includes('manage_roles')
  );

  if (!hasPermission) {
    throw new ApiError(403, "You don't have permission to manage roles");
  }

  // Check if target user exists in server
  const targetMemberIndex = server.members.findIndex(m => 
    m.userId.toString() === targetUserId
  );

  if (targetMemberIndex === -1) {
    throw new ApiError(404, "Target user is not a member of this server");
  }

  // Can't modify the owner's roles
  if (server.owner.toString() === targetUserId) {
    throw new ApiError(403, "Cannot modify the server owner's roles");
  }

  // Verify all roles exist
  const validRoles = server.roles.map(r => r.name);
  const invalidRoles = roles.filter(r => !validRoles.includes(r));
  
  if (invalidRoles.length > 0) {
    throw new ApiError(400, `Invalid roles: ${invalidRoles.join(', ')}`);
  }

  // Update member's roles
  server.members[targetMemberIndex].roles = roles;
  await server.save();

  // Update the user's server entry
  await User.findOneAndUpdate(
    { 
      _id: targetUserId,
      "servers.serverId": serverId 
    },
    {
      $set: { "servers.$.roles": roles }
    }
  );

  res.status(200).json(
    new ApiResponse(200, {}, "Member roles updated successfully")
  );
});

// Kick a member from the server
const kickMember = asyncHandler(async (req: Request, res: Response) => {
  const { serverId, userId: targetUserId } = req.params;
  const userId = req.user?._id;

  if (!userId) {
    throw new ApiError(401, "User not authenticated");
  }

  // Check if server exists
  const server = await Server.findById(serverId);
  if (!server) {
    throw new ApiError(404, "Server not found");
  }

  // Check if current user has permission
  const member = server.members.find(m => m.userId.toString() === userId.toString());
  if (!member) {
    throw new ApiError(403, "You are not a member of this server");
  }

  const isOwner = server.owner.toString() === (userId as any).toString();
  const userRoles = member.roles;
  const hasPermission = isOwner || userRoles.includes('admin') || server.roles.some(role => 
    userRoles.includes(role.name) && role.permissions.includes('kick_members')
  );

  if (!hasPermission) {
    throw new ApiError(403, "You don't have permission to kick members");
  }

  // Check if target user exists in server
  const targetMemberIndex = server.members.findIndex(m => 
    m.userId.toString() === targetUserId
  );

  if (targetMemberIndex === -1) {
    throw new ApiError(404, "Target user is not a member of this server");
  }

  // Can't kick the owner
  if (server.owner.toString() === targetUserId) {
    throw new ApiError(403, "Cannot kick the server owner");
  }

  // Check if target has higher role than the user
  const targetMember = server.members[targetMemberIndex];
  
  // Get highest role positions for both users
  const getHighestRolePosition = (memberRoles: string[]) => {
    const positions = memberRoles.map(roleName => {
      const role = server.roles.find(r => r.name === roleName);
      return role ? role.position : 0;
    });
    return Math.max(...positions, 0);
  };

  const userPosition = getHighestRolePosition(userRoles);
  const targetPosition = getHighestRolePosition(targetMember.roles);

  // Can only kick users with lower role position (unless owner)
  if (!isOwner && targetPosition >= userPosition) {
    throw new ApiError(403, "You can only kick members with lower roles than yourself");
  }

  // Remove user from server members
  server.members.splice(targetMemberIndex, 1);
  await server.save();

  // Remove server from user's server list
  await User.findByIdAndUpdate(
    targetUserId,
    { $pull: { servers: { serverId } } }
  );

  res.status(200).json(
    new ApiResponse(200, {}, "Member kicked successfully")
  );
});

// Add this new controller method
const joinServerByCode = asyncHandler(async (req: Request, res: Response) => {
  const { inviteCode } = req.params;
  const userId = req.user?._id;

  if (!inviteCode) {
    throw new ApiError(400, "Invite code is required");
  }

  // Find the server that has this invite code
  const server = await Server.findOne({
    "inviteCodes.code": inviteCode,
    "inviteCodes.expiresAt": { $gt: new Date() }, // Make sure it's not expired
    "inviteCodes.uses": { $lt: "$inviteCodes.maxUses" } // Make sure it hasn't exceeded max uses
  });

  if (!server) {
    throw new ApiError(404, "Invalid or expired invite code");
  }

  // Check if user is already a member
  const isAlreadyMember = server.members.some(member => 
    member.userId.toString() === userId?.toString()
  );

  if (isAlreadyMember) {
    throw new ApiError(400, "You are already a member of this server");
  }

  // Add user to server members
  server.members.push({
    userId: userId as any,
    joinedAt: new Date(),
    roles: []
  });

  // Increment the invite code usage
  const inviteIndex = server.inviteCodes.findIndex(invite => invite.code === inviteCode);
  if (inviteIndex !== -1) {
    server.inviteCodes[inviteIndex].uses += 1;
  }

  await server.save();

  // Populate the server with member details
  const populatedServer = await Server.findById(server._id)
    .populate('members.userId', 'username displayName avatarUrl status')
    .populate('owner', 'username displayName avatarUrl');

  res.status(200).json(
    new ApiResponse(200, populatedServer, "Successfully joined server")
  );
});

// Export the new function
export {
  createChannel, createInvite, createServer, deleteChannel, deleteServer, getServerDetails, getServerMembers, getUserServers, joinServer, joinServerByCode, kickMember, leaveServer, updateChannel, updateMemberRoles, updateServer
};

