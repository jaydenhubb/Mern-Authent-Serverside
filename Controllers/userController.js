const asynHandler = require("express-async-handler");
const User = require("../Model/UserModel");
const bcrypt = require("bcryptjs");
const { createToken, hashToken } = require("../utils");
const sendEmail = require("../utils/sendEmail");
const parser = require("ua-parser-js");
const jwt = require("jsonwebtoken");
const Token = require("../Model/TokenModel");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const cryptr = new Cryptr(process.env.CRYPTR_KEY);
const {OAuth2Client} = require("google-auth-library")
const client = new OAuth2Client(process.env.CLIENT_ID)

// Create User
const registerUser = asynHandler(async (req, res) => {
  const { name, email, password } = req.body;
  //   validate
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please fill in required fields");
  }
  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be greater than 6 characters");
  }
  // Check if user exists

  const exists = await User.findOne({ email });
  if (exists) {
    res.status(400);
    throw new Error("This email has already been used");
  }

  // Get user agent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // create new user
  const user = await User.create({ name, email, password, userAgent });

  // Generate Token
  const token = createToken(user._id);

  //send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), //one day
    sameSite: "none",
    secure: true,
  });
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(400);
    throw new Error("invalid user data");
  }
});

// send verification email
const sendVMail = asynHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("Email was not found");
  }
  if (user.isVerified) {
    res.status(400);
    throw new Error("User already verified");
  }
  // Delete verification token if it exists
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }
  // create a verification token and save
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;

  // hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    vToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000),
  }).save();

  //   construct verification url

  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  //send Email

  const subject = "Verify Your Account - Auth-jay";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "jaydenblakelex@gmail.com";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
    res.status(200).json({ Message: "Verification Email sent" });
  } catch (err) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// Log in user
const loginUser = asynHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400);
    throw new Error("Please fill in required fields");
  }
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("Email was not found, please sign up");
  }
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    res.status(404);
    throw new Error("Invalid email or password");
  }
  // Trigger 2FA for unknown userAgent
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent = ua.ua;
  const allowedAgent = user.userAgent.includes(thisUserAgent);
  if (!allowedAgent) {
    // Generate 6 digit code
    const loginCode = Math.floor(100000 + Math.random() * 9000);
    // encrypt login code before saving to db
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());
    // Delete verification token if it exists
    let usertoken = await Token.findOne({ userId: user._id });
    if (usertoken) {
      await usertoken.deleteOne();
    }
    // save token to db

    await new Token({
      userId: user._id,
      lToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000),
    }).save();
    res.status(400);
    throw new Error("New browser or device detected, check your mail to verify device/browser");
  }

  //   Generate token
  const token = createToken(user._id);
  if (user && validPassword) {
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), //one day
      sameSite: "none",
      secure: true,
    });
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(500);
    throw new Error("Something went wrong, please try again");
  }
});

// Send Login code via Email
const sendLoginCode = asynHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  // Find login token in db
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired Token, please login again");
  }
  const loginCode = userToken.lToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);

  // Send login code to mail
  const subject = "Login access code - Auth-jay";
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "jaydenblakelex@gmail.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
    res.status(200).json({ Message: "Login code sent" });
  } catch (err) {
    res.status(500);
    throw new Error("Login code not sent, please try again");
  }
});

// Login with access code
const loginWithCode = asynHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // find user login token

  const userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token, please login again");
  }
  const decryptedLoginCode = cryptr.decrypt(userToken.lToken);
  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, please try again");
  } else {
    // register user Agent
    const ua = parser(req.headers["user-agent"]);
    const thisuserAgent = ua.ua;
    user.userAgent.push(thisuserAgent);
    await user.save();

    // Generate Token
    const token = createToken(user._id);

    //send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), //one day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

// Verify user
const verifyUser = asynHandler(async (req, res) => {
  const { verificationToken } = req.params;
  const hashedToken = hashToken(verificationToken);
  const userToken = await Token.findOne({
    vtoken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token");
  }
  // find User

  const user = await User.findById(userToken.userId);

  if (user.isVerified) {
    res.status(400);
    throw new Error("User is already verified");
  }

  //verify User

  user.isVerified = true;
  await user.save();
  res.status(200).json({ message: "Account verification successful" });
});

// Log out
const logOutUser = asynHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ Message: "Logout successful" });
});

// Get User
const getUser = asynHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

// Update User
const updateUser = asynHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { name, email, phone, bio, photo, role, isVerified } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    });
  } else {
    res.status(404);
    throw new Error("user not found");
  }
});

// Delete user

const deleteUser = asynHandler(async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  } else {
    await user.deleteOne();
    res.status(200).json({ message: "user deleted" });
  }
});

// Get users
const getUsers = asynHandler(async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).select("-password");
  if (!users) {
    res.status(500);
    throw new Error("Something went wrong");
  } else {
    res.status(200).json(users);
  }
});

// Get login status
const loginStatus = asynHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  // verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  } else {
    return res.json(false);
  }
});

// upgrade User

const upgradeUser = asynHandler(async (req, res) => {
  const { role, id } = req.body;
  const user = await User.findById(id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  user.role = role;
  await user.save();
  res.status(200).json({ Message: `User role updated to ${role}` });
});

// send mail
const sendMail = asynHandler(async (req, res) => {
  const {subject, send_to, reply_to, template, url } = req.body;
  if (!subject || !send_to || !reply_to || !template) {
    res.status(404);
    throw new Error("Missing email parameter");
  }
  //   get user
  const user = await User.findOne({ email: send_to });
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url}`;
  //
  try {
    sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
    res.status(200).json({ message: "Confirmation Email sent" });
  } catch (err) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// forgot Password

const forgotPassword = asynHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    res.status(404);
    throw new Error("No user with this email");
  }
  // Delete reset token if it exists
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }
  // create a reset token and save
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;

  // hash token and save
  const hashedToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    rToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000),
  }).save();

  //   construct reset url

  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  //send Email

  const subject = "Reset Your Password - Auth-jay";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@gmail.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
    res.status(200).json({ Message: "Password Reset Email sent" });
  } catch (err) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// Reset Password
const resetPassword = asynHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  const hashedToken = hashToken(resetToken);
  const userToken = await Token.findOne({
    rtoken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token");
  }
  // find User

  const user = await User.findById(userToken.userId);

  //Reset User Password

  user.password = password;
  await user.save();
  res.status(200).json({ message: "Password Reset successful, please Login" });
});

// Change Password

const changePassword = asynHandler(async (req, res) => {
  const { oldPassword, password } = req.body;
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  if (!oldPassword || !password) {
    res.status(404);
    throw new Error("Please enter old and new password");
  }
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  if (passwordIsCorrect) {
    user.password = password;
    await user.save();
    res.status(200).json({ message: "Password change successful" });
  } else {
    res.status(400);
    throw new Error("Old password is incorrect");
  }
});

// Login with google

const loginWithGoogle = asynHandler(async (req, res)=>{
  const {userToken} = req.body
  // console.log(userToken)
  // res.send("Google Login")
  const ticket = await client.verifyIdToken({
    idToken:userToken, 
    audience: process.env.CLIENT_ID
  })
  const payload = ticket.getPayload()
  const {name, email, picture, sub } = payload
  const password = Date.now()+ sub
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];
  // console.log(payload);
  const user = await User.findOne({email})
  if (!user){
    const newUser = await User.create({ name, email, password, userAgent, photo:picture, isVerified:true, userAgent });
  
    // Generate Token
    if(newUser){
      const token = createToken(newUser._id);
    
      //send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), //one day
        sameSite: "none",
        secure: true,
      })

      const { _id, name, email, phone, bio, photo, role, isVerified } = newUser;
      console.log(_id, name, email, phone, bio, photo, role, isVerified);
    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
    }
  }
  if(user){
    const token = createToken(user._id);
    
      //send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), //one day
        sameSite: "none",
        secure: true,
      })
      const { _id, name, email, phone, bio, photo, role, isVerified } = user;
      res.status(201).json({
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        token,
      })
  }
});



module.exports = {
  
  registerUser,
  loginUser,
  logOutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendMail,
  sendVMail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle
};
