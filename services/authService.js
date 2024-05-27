const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const asyncHandler = require("express-async-handler");
const ApiError = require("../utils/apiError");

const User = require("../models/userModel");

const generateToken = (payload) => {
  const token = jwt.sign({ userId: payload }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  }); // 1. Generate token
  return token;
};

// @desc Signup
// @route POST /api/v1/auth/signup
// @access Public

exports.signup = asyncHandler(async (req, res, next) => {
  // 1. Create new user
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
  });
  // 2. Generate token
  const token = generateToken(user._id);
  // 3. Send response
  res.status(201).json({ data: user, token });
});

// @desc Login
// @route POST /api/v1/auth/login
// @access Public
exports.login = asyncHandler(async (req, res, next) => {
  // 1. check if password and email in the body (validation)
  // 2. check if user exists & check if password is correct
  const user = await User.findOne({ email: req.body.email });
  const isMatch = await bcrypt.compare(req.body.password, user.password);
  if (!user || !isMatch) {
    return next(new ApiError("Invalid email or password", 401));
  }
  // 3.generaion of token
  const token = generateToken(user._id);
  // 4. send response to client side
  res.status(200).json({ data: user, token });
});

exports.protect = asyncHandler(async (req, res, next) => {
  // 1. check if token exists, if exists then extract token
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
    console.log(token);
  }

  if (!token) {
    return next(new ApiError("You are not logged in! Please login", 401));
  }
  // 2. verify token (no changes happen, no expiration, signature is valid)
  // 3. check if user still exists
  // 4. check if user changed password after the token was issued
});
