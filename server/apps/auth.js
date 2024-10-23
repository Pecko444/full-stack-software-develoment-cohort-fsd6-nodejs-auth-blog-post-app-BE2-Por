import { Router } from "express";
import { db } from "../utils/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();//load environment

const authRouter = Router();

// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้

authRouter.post('/register', async (req, res) => {
    //assign request body into variable
    const user = {
        username: req.body.username,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
    };

    //encrpt password from req
    const salt = await bcrypt.genSalt(10);
    // set password to Hash-PW
    user.password = await bcrypt.hash(user.password, salt);

    const collection = db.collection('users');
    await collection.insertOne(user)

    return res.json({
        message: 'User has been created successfully'
    });
    
})

// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้
authRouter.get('/login', async (req, res) => {
    const user = await db.collection("users").findOne({
        username: req.body.username,
    });

    //error handling when cannot find user
    if (!user) {
        return res.status(404).json({message: `user's not found `})
    };

    //validate process
    const isValidPassword = await bcrypt.compare(
        req.body.password, //password from req
        user.password // password from database
    );

    // error handling when password not valid
    if (!isValidPassword) {
        return res.status(401).json({message: ` Invalid username or password`})
    };

    //create token
    const token = jwt.sign(
        { id: user._id, firstName: user.firstName, lastName: user.lastName },
        process.env.SECRET_KEY,
        {
            expiresIn: "900000",
        }
    );

    return res.json({
        message: `login successfully`,
        token,
    });
});


export default authRouter;
