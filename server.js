const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const authRouter = require("./auth/router.js");
const usersRouter = require("./users/router.js");
const restricted = require("./auth/middleware.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use("/api/auth", authRouter);
server.use("/api/users", restricted, usersRouter);

server.get("/", (req, res) => {
  res.json({ api: "up" });
});

module.exports = server;
