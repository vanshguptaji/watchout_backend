import express, { urlencoded } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
// import { createServer } from "http";
// import { Server } from "socket.io";
import userRouter from "./routes/user.routes";

const app = express();
// const httpServer = createServer(app);
// const io = new Server(httpServer, {
//   cors: {
//     origin: process.env.CORS_ORIGIN,
//     methods: ["GET", "POST"],
//     credentials: true,
//   },
//   connectionStateRecovery: {
//     maxDisconnectionDuration: 2 * 60 * 1000,
//     skipMiddlewares: false,
//   },
// });

// io.on("connection", (socket) => {
//   // ...
// });

// httpServer.listen(3030);

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

app.use("/api/v1/user", userRouter);


export { app };
