const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { JWT_SECRET } = require("../secrets");
const { tokenBuilder } = require("./tokenbuilder");
const Users = require("./../users/users-model");

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
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
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
 if(!req.decodeJwt.role_name === role_name){
   return next({status:403,message:'This is not for you'})
 }
 next()
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
 const validUsername = req.body
 if(!validUsername){
   next({status:401, message:"Invalid credentials"})
 }
 else{
   next()
 }
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
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
