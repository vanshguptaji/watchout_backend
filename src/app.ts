import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import messageRouter from "./routes/message.routes";
import serverRouter from "./routes/server.routes";
import userRouter from "./routes/user.routes";

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CORS_ORIGIN,
    methods: ["GET", "POST"],
    credentials: true,
  },
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000,
    skipMiddlewares: false,
  },
});

// Socket.io connection handling
io.on("connection", (socket) => {
  console.log(`Socket connected: ${socket.id}`);

  // Join user to their specific room for notifications
  socket.on("join-user", (userId) => {
    socket.join(`user:${userId}`);
  });

  // Join server channels
  socket.on("join-server", (serverId) => {
    socket.join(`server:${serverId}`);
  });

  // Join specific channel
  socket.on("join-channel", (serverId, channelId) => {
    socket.join(`channel:${serverId}:${channelId}`);
  });

  // Join DM conversation - fix the room joining
  socket.on("join-dm", (conversationId) => {
    socket.join(`dm:${conversationId}`);
    console.log(`User joined DM room: dm:${conversationId}`);
  });

  // Handle typing indicator
  socket.on("typing", (data) => {
    if (data.channelId) {
      socket
        .to(`channel:${data.serverId}:${data.channelId}`)
        .emit("typing", {
          userId: data.userId,
          username: data.username,
          isTyping: data.isTyping,
        });
    } else if (data.directMessageId) {
      socket.to(`dm:${data.directMessageId}`).emit("typing", {
        userId: data.userId,
        username: data.username,
        isTyping: data.isTyping,
      });
    }
  });

  socket.on("disconnect", () => {
    console.log(`Socket disconnected: ${socket.id}`);
  });
});

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  })
);

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());

// API routes
app.use("/api/v1/users", userRouter);
app.use("/api/v1/servers", serverRouter);
app.use("/api/v1/messages", messageRouter);

export { app, httpServer, io };

