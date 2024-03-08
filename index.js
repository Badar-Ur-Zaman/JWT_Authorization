import express from "express";
import jwt from "jsonwebtoken"
const app = express();
app.use(express.json());

const users = [
  { id: 1, username: "mosin", password: "andjaN123", isAdmin: false },
  { id: 2, username: "jane", password: 'adjkcw23r`', isAdmin: false },
  { id: 3, username: "john", password: "dskjhK1331", isAdmin: true },
];

const generateAccessToken = (user)=>{
  return jwt.sign({
    id:user.id,
    isAdmin:user.isAdmin
  }, "myAccessToken", {expiresIn:"10m"});
}
const generateRefreshToken = (user)=>{
  return jwt.sign({
    id:user.id,
    isAdmin:user.isAdmin
  }, "myRefreshToken");
}

let refreshTokens = [];

app.post("/login", (req,res)=>{
    const {username, password} = req.body;
    const user = users.find((u)=>{
        return u.username === username && u.password === password;
    });
    if(user){
      //generate access token
      const accesstoken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);
      refreshTokens.push(refreshToken);

      res.json({
        username:user.username,
        isAdmin:user.isAdmin,
        accesstoken,
        refreshToken
      });

    }else{
      return res.status(400).json("Username or password is incorrect.");
    }
});

app.post("/refresh", (req, res)=>{
  const refreshToken = req.body.token;
  if(!refreshToken){
    return res.status(401).json("Not Authenticated");
  }
  if(!refreshTokens.includes(refreshToken)){
    return res.status(403).json("Token is not valid");
  }
  jwt.verify(refreshToken, "myRefreshToken", (err, data)=>{
    err & console.log(err);
    refreshTokens = refreshTokens.filter((token)=> token !== refreshToken);
    const newAccessToken = generateAccessToken(data);
    const newRefreshToken = generateRefreshToken(data);
    refreshTokens.push(newRefreshToken);
    res.status(200).json({
      accesstoken:newAccessToken,
      refreshToken:newRefreshToken
    });
  })
});

const tokenVerification = (req,res,next) => {
  const authHeader = req.headers.authorization;

  if(authHeader){

    const authKey = authHeader.split(" ")[1];
    jwt.verify(authKey, "mysecretkey", (err, data)=>{
      if(err){
        return res.status(403).json("Token is not valid");
      
      }else{

        req.user = data;
        next();
      }
    });
  }else{
    return res.status(401).json("Unauthorized Access");
  }
};

app.post("/logout", tokenVerification, (req, res)=>{
  const token = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== token);
  res.status(200).json("Logout successfully!")
});

app.delete("/delete/user/:userId", tokenVerification, (req,res)=>{
  if(req.user.id === req.params.userId || req.user.isAdmin){
    return res.status(200).json("User has been deleted successfully");
  }else{
    res.status(403).json("You're NOT authenticated to delete");
  }
})

app.listen(5000, () => {
  console.log("Backend Started Running!");
});
