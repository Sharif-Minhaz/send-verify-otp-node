```js
const User = require("../modal/passportSchema");
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
require("dotenv").config();
const crypto = require('crypto');
const transporter = require("../config/nodemailer");

// সব ব্যবহারকারী দেখতে
const allUser = async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json(users);
    } catch (error) {
        res.status(404).json({ message: error.message });
    }
};

// রেজিস্ট্রেশন ফাংশন
const registryPost = async (req, res) => {
    try {
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            return res.status(400).send("User already exists");
        }

        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

        // নতুন ব্যবহারকারী তৈরি করা
        const newUser = new User({
            email: req.body.email,
            password: hashedPassword
        });

        // ডাটাবেজে সেভ করা
        await newUser.save();

        // সাফল্যের বার্তা
        res.send({
            success: true,
            message: "User is created successfully",
            newUser: {
                id: newUser._id,
                email: newUser.email,
            }
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// লগইন ফাংশন
const loginPost = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ 
                success: false,
                message: "User not found" 
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(402).json({ 
                success: false,
                message: "Wrong password" 
            });
        }
        
        const payload = { id: user._id, email: user.email }; // Example payload
        const token = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '2d' });

        return res.status(200).json({
            success: true,
            token: `Bearer ${token}`
        });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};

// Send OTP for password reset

const generateOtp = () => {
    const otp = Math.floor(100000 + Math.random() * 900000); // ৬-ডিজিটের সংখ্যা তৈরি করা
    return otp.toString();
};

const sendOTP = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // ৬-ডিজিটের OTP তৈরি করা
        const otp = generateOtp();
        const otpExpires = Date.now() + 10 * 60 * 1000; // ১০ মিনিটের মেয়াদ

        // OTP এবং expiry টাইম সেভ করা
        user.otp = otp;
        user.otpExpires = otpExpires;
        await user.save();

        // OTP ইমেইল পাঠানো
        await transporter.sendMail({
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Your OTP for Password Reset',
            text: `Your OTP is ${otp}. It will expire in 10 minutes.`
        });

        res.status(200).json({ message: "OTP sent to your email" });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};



// OTP verification
const verifyOTP = async (req, res) => {
    try {
        const { otp } = req.body;

        // ইমেইল থেকে ব্যবহারকারী খুঁজে বের করুন
        const user = await User.findOne({ otp });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // OTP এবং মেয়াদ যাচাই
        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        // OTP সফলভাবে যাচাই হলে, নতুন পাসওয়ার্ড রিসেট করতে পারবেন
        res.status(200).json({ message: "OTP verified" });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};



// Reset password
// Reset password
const resetPassword = async (req, res) => {
    try {
        const { newPassword, email } = req.body;

        // ইমেইল থেকে ব্যবহারকারী খুঁজে বের করুন
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // নতুন পাসওয়ার্ড হ্যাশ করা
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        // OTP রিসেট করা
        user.otp = null;
        user.otpExpires = null;

        await user.save();

        res.status(200).json({ message: "Password reset successful" });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};




module.exports = { allUser, registryPost, loginPost ,sendOTP,verifyOTP,resetPassword};
```
