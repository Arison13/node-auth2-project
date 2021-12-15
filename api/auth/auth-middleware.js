const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { JWT_SECRET } = require("../secrets");
const { tokenBuilder } = require("./tokenbuilder");
const Users = require("./../users/users-model");


const restricted = (req, res, next) => {
  
    const token = req.headers.authorization
    if(!token){
      return next({status:401, message:'Token required'})
    }
    jwt.verify(token, JWT_SECRET, (err, decoded)=> {
      if(err){
        return next({status:401, message: 'Token invalid'})
      }
      req.decodeJwt = decoded
      next()
    })
}

const only = role_name => (req, res, next) => {
  
 if(req.decodeJwt.role_name === role_name){
  next()
 }else {
   next({status:403 ,message:'This is not for you'})
 }
}


const checkUsernameExists = async (req, res, next) => {
 
 const validUsername = req.body
 if(!validUsername){
   next({status:401, message:"Invalid credentials"})
 }
 else{
   next()
 }
}

const validateRoleName = (req, res, next) => {
  
  const role_name = req.body.role_name
  if(!role_name || role_name.trim().length < 1) {
    req.body.role_name = 'student'
    next()
  }else if (role_name.trim() === 'admin'){
    next({status:422, message:'Role name can not be admin'})
  }else if(role_name.trim().length > 32) {
    next({status:422, message:"Role name can not be longer than 32 chars"})
  }else{
    req.body.role_name = role_name.trim()
    next()
  }
}


const checkPasswordCorrect = async (req, res, next) => {
  let { username, password } = req.body;

  const validUser = await Users.findBy({ username: username });

  if (validUser && bcrypt.compareSync(password, validUser.password)) {
    const token = tokenBuilder(validUser);
    req.token = token;
    next();
  } else {
    next({ status: 401, message: "Invalid Credentials" });
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  checkPasswordCorrect,
}
