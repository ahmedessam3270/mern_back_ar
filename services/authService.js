const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const ApiError = require("../utils/apiError");

const User = require("../models/userModel");

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
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
  // 3. Send response
  res.status(201).json({ data: user, token });
});
