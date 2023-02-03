const asynHandler = require("express-async-handler");
const User = require("../Model/UserModel");
const jwt = require("jsonwebtoken");

const protect = asynHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      res.status(400);
      throw new Error("Not Authorized, Please log in");
    }
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(verified.id).select("-password");
    if (!user) {
      res.status(404);
      throw new Error("User not found ");
    }
    if (user.role === "suspended") {
      res.status(400);
      throw new Error("User suspended, please contact support ");
    }
    req.user = user;
    next();
  } catch (error) {
    res.status(401);
    throw new Error("Not Authorized, Please log in");
  }
});

const adminOnly = asynHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("Not authorized as an admin");
  }
});
const authorOnly = asynHandler(async (req, res, next) => {
  if (req.user.role === "admin" || req.user.role === "author") {
    next();
  } else {
    res.status(401);
    throw new Error("Not authorized as an author");
  }
});
const verifiedOnly = asynHandler(async (req, res, next) => {
  if (req.user && req.user.isverified) {
    next();
  }
  res.status(401);
  throw new Error("Not authorized. Account not verified");
});
module.exports = { protect, adminOnly, verifiedOnly, authorOnly };
