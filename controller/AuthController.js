const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const config = require('../config');
const User = require('../model/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json());

//all users
router.get('/users',(req,res)=>{
    User.find({},(err,data)=>{
        if(err) throw err
        res.send(data);
    
    })
});

//register
router.post('/register',(req,res)=>{
    let hashpass = bcrypt.hashSync(req.body.password,8);
    User.create({
        name:req.body.name,
        email:req.body.email,
        password:hashpass,
        phone:req.body.phone,
        username:req.body.username?req.body.username:'user'
    },(err,result)=>{
        if(err) res.send("unable to register")
        res.send("registered successfully")
    })
});

//login

router.post('/login',(req,res)=>{
    User.findOne({email:req.body.email},(err,user)=>{
        if(err) return res.send({auth:false,token:"error while logging in"})
        if(!user) return res.send({auth:false,token:"no user found"})
        else{
            let validPass = bcrypt.compareSync(req.body.password,user.password);
            if(!validPass) res.send({auth:false,token:"wrong password"})
            let token = jwt.sign({id:user._id},config.secret,{expiresIn:86400});
            res.send({auth:true,token:token})
        }
    })
})


//userinfo

router.get('/userinfo',(req,res)=>{
    let token = req.headers['x-access-token'];
    if(!token) return res.send({auth:false,token:"no token provided"})
    jwt.verify(token,config.secret,(err,user)=>{
        if(err) return res.send({auth:false,token:"invalid token"})
        User.findById(user.id,(err,result)=>{
            if(err) throw err
            res.send(result)
        })
    })
})




module.exports = router;