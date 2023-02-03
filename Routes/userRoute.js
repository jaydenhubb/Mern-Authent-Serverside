const express = require('express')
const router = express.Router()
const {
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
  loginWithGoogle,
} = require("../Controllers/userController");
const { protect, adminOnly, authorOnly } = require('../Middleware/authMiddleware')

router.post('/register', registerUser)
router.post('/login', loginUser)
router.get('/logout', logOutUser)
router.get('/getUsers',protect, authorOnly,  getUsers)
router.get('/getUser', protect, getUser)


router.patch('/updateUser',protect, updateUser)
router.delete('/:id',protect, adminOnly, deleteUser)
router.get('/loginStatus', loginStatus)
router.post("/upgradeUser", protect, adminOnly, upgradeUser);
router.post("/sendMail", protect, sendMail);

router.post("/sendVMail", protect, sendVMail)
router.patch("/verifyUser/:verificationToken", verifyUser);
router.post("/forgotPassword", forgotPassword);
router.patch("/resetPassword/:resetToken", resetPassword);
router.patch("/changePassword", protect, changePassword);


router.post("/google/callback", loginWithGoogle)
router.post("/sendLoginCode/:email", sendLoginCode);
router.post("/loginWithCode/:email", loginWithCode);




module.exports = router