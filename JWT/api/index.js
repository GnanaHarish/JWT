const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
require("dotenv").config();
app.use(express.json());

const users = [
    {
        id: "1",
        usernname: "Monkey D Luffy",
        password: process.env.MDLPASS,
        isAdmin: true
    },
    {
        id: "2",
        usernname: "Roronoa Zoro",
        password: process.env.ZOROPASS,
        isAdmin: false
    }
]

let refreshTokens = [];
const generateAccessToke = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.SECRETKEY, { expiresIn: "15m" });
}

const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.REFRESHKEY)
}

app.post("/api/refresh", (req, res) => {
    const refreshToken = req.body.refreshtoken;
    if (!refreshToken) {
        res.status(403).json("You are not authorized to do that!")
    }
    if (!refreshTokens.includes(refreshToken)) {
        res.status(403).json("Refresh Token is invalid");
    }
    jwt.verify(refreshToken, process.env.REFRESHKEY, (err, user) => {
        if (err) {
            console.log(err);
        }
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

        const newAccessToken = generateAccessToke(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            newAccessToken: newAccessToken,
            newRefreshToken: newRefreshToken
        })
    })
})
app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.find((u) => {
        return u.usernname === username && u.password === password;
    })
    if (user) {
        const accesstoken = generateAccessToke(user);
        const refreshtoken = generateRefreshToken(user);
        refreshTokens.push(refreshtoken);
        res.status(200).json({
            username: user.usernname,
            password: user.password,
            accesstoken,
            refreshtoken
        });
    }
    else {
        res.status(400).json("Invalid Credentials");
    }

})

const verify = (req, res, next) => {
    const authHeader = req.headers.token;
    if (authHeader) {
        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.SECRETKEY, (err, user) => {
            if (err) {
                return res.status(403).json("Token is invalid");
            }

            req.user = user;
            next();
        })
    }
    else {
        res.status(401).json("You are not authorized user");
    }
}

app.post("/api/logout", verify, (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json("You are sucessfully logged out");
})
app.delete("/api/users/:userId", verify, (req, res) => {
    if (req.user.id === req.params.userId || req.user.isAdmin) {
        res.status(200).json("User has been deleted");
    }
    else {
        res.status(403).json("You are not authorized to do that!");
    }
})

app.listen(process.env.PORT || 5000, () => {
    console.log("Backend Server is running");
})