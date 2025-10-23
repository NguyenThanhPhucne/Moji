import bcrypt from "bcrypt";
import User from "../models/User.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import Session from "../models/Session.js";

const ACCESS_TOKEN_TTL = "30m";
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000;

export const signUp = async (req, res) => {
  try {
    const { username, password, email, firstName, lastName } = req.body;

    if (!username || !password || !email || !firstName || !lastName) {
      return res.status(400).json({
        message:
          "Không thể thiếu username, password, email, firstName và lastName",
      });
    }

    //Kiểm tra user có tồn tại chưa
    const duplicate = await User.findOne({ username });
    if (duplicate) {
      return res.status(409).json({ message: "User đã tồn tại" });
    }

    // Mã hoá password
    const hashedPassword = await bcrypt.hash(password, 10); // salt = 10

    // Tạo user mới
    await User.create({
      username,
      hashedPassword,
      email,
      displayName: `${firstName} ${lastName}`,
    });

    // return
    return res.sendStatus(204);
  } catch (error) {
    console.error("Lỗi khi gọi Sign Up", error);
    return res.status(500).json({ message: "Lỗi hệ thống hi gọi Sign up" });
  }
};

export const signIn = async (req, res) => {
  try {
    // Lấy inputs
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Thiếu username hoặc password!" });
    }

    // Lấy hashedPassword trong db để so với password input
    const user = await User.findOne({ username });

    if (!user) {
      return res
        .status(401)
        .json({ message: "Username hoặc password không chính xác" });
    }

    // Kiểm tra Password
    const passwordCorrect = await bcrypt.compare(password, user.hashedPassword);

    if (!passwordCorrect) {
      return res
        .status(401)
        .json({ message: "Username hoặc password không chính xác" });
    }

    // Nếu khớp, tạo accessToken với JWT
    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL }
    );

    // Tạo refresh token
    const refreshToken = crypto.randomBytes(64).toString("hex");

    // Tạo session mới để lưu refresh token
    await Session.create({
      userId: user._id,
      refreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
    });
    // Trả refresh token về trong cookie

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: REFRESH_TOKEN_TTL,
    });
    // Trả access về trong Respond

    return res.status(200).json({
      message: `User ${user.displayName} đã logged in`,
      accessToken: accessToken,
    });
  } catch (error) {
    console.error("Lỗi khi gọi Sign In", error);
    return res.status(500).json({ message: "Lỗi hệ thống hi gọi Sign in" });
  }
};

export const signOut = async (req, res) => {
  try {
    // Lấy refresh token từ cookie
    const token = req.cookies?.refreshToken;

    if (token) {
      // Xoá refresh token trong Session
      await Session.deleteOne({ refreshToken: token });

      // Xoá cookie
      res.clearCookie("refreshToken");
    }

    return res.sendStatus(204);
  } catch (error) {
    console.error("Lỗi khi gọi Sign Out", error);
    return res.status(500).json({ message: "Lỗi hệ thống khi gọi Sign out" });
  }
};
/*

đã có trong postman
{ 
    "username": "User1", 
    "password": "abc", 
    "email": "phucabc987@gmail.com", 
    "firstName": "Thanh", 
    "lastName": "Phuc"
}
*/
