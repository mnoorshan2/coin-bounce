const Joi = require('joi');
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const userDto = require('../dto/user');
const JWTServices = require('../services/JWTServices');
const RefreshToken = require('../models/token')



const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,25}$/;
const authController = {
    async register(req, res, next) {
        // 1. validate user input
        const userRegisterSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            name: Joi.string().max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().pattern(passwordPattern).required(),
            confirmPassword: Joi.ref('password')
        })

        const {error} = userRegisterSchema.validate(req.body)

        // 2. if error in validation => return error
        if(error) {
            return next(error);
        }
        // 3. if username or email is already exists => return an error
        const { username, email, password, name } = req.body;
        console.log(username);

        try{
            const emailInUse = await User.exists({email});
            const usernameInUse = await User.exists({username});

            if(emailInUse){
                const error = {
                    status : 409,
                    message: 'user already registered, use another email'
                }
                return next(error);
            }

            if(usernameInUse){
                const error = {
                    status: 409,
                    message: 'Username is not available, choose4 another username'
                }

                return next(error);
            }
        }
        catch(error){
            return next(error);
        }
        // 4. password hash
        const hashedPassword = await bcrypt.hash(password, 10);
        // 5. store data in db
        let accessToken;
        let refreshToken;
        let user;

        try{
            const userToRegister = new User({
                username,
                email,
                name,
                password: hashedPassword
            })
    
            user = await userToRegister.save();
            // token generation
            accessToken = JWTServices.signAccessToken({_id: user._id}, '30m');

            refreshToken = JWTServices.signRefreshToken({_id: user._id}, '60m')

        }
        catch(error){
            return next(error);
        }

        await JWTServices.storeRefreshToken(refreshToken, user._id)
        // send token in cookie
        res.cookie('accessToken', accessToken, {
            maxAge: 1000 * 60 * 60 * 24 * 7,
            httpOnly: true
        });

        res.cookie('refreshToken', refreshToken, {
            maxAge: 1000 * 60 * 60 * 24 * 7,
            httpOnly: true
        });
        
        // 6. response send2
        const UserDto = new userDto(user);
        return res.status(209).json({UserDto, auth: true})
    },
    async login(req, res, next) {
        // 1. validate user input
        // 2. if validation error return error
        // 4. return response

        // we expect input data to be in shape
        const userLoginSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            password: Joi.string().pattern(passwordPattern).required(),
        })

        const {error} = userLoginSchema.validate(req.body);

        if(error){
            return next(error);
        }

        const {username, password} = req.body;

        // 3. match username and password
        let user;
        try{
            // match username
            user = await User.findOne({username: username});

            if(!user){
                const error = {
                    status: 401,
                    message: 'invalid username or password',
                }
                return next(error);
            }

            // password mach
            // req.body.password => hash -> match
            const match = await bcrypt.compare(password, user.password);

            if(!match){
                const error = {
                    status: 401,
                    message: 'invalid password'
                }
                return next(error)
            }
        }
        catch(error){
            return next(error);

        }

       const accessToken = JWTServices.signAccessToken({_id: user._id}, '30m');
       const refreshToken = JWTServices.signRefreshToken({_id: user._id}, '60m');

       // update refresh token in database
       try{
        
           await RefreshToken.updateOne({
               _id: user._id
           },
           {token: refreshToken},
           {upsert: true}
           )
       }
       catch(error){
        return next(error);
       }

       res.cookie('accessToken', accessToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true
       })

       res.cookie('refreshToken', refreshToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true
       })

        const UserDto = new userDto(user);

        return res.status(200).json({user: UserDto, auth: true})
    },
    async logout(req, res, next){
        console.log(req)
        // 1. delete refresh token from db
        const {refreshToken} = req.cookies;
        try{
            RefreshToken.deleteOne({token: refreshToken});

        }
        catch(error){
            return next(error);
        }
        // delete cookies
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        // 2. response
        res.status(200).json({user: null, auth: false});
    },

    async refresh(req, res, next){
        // 1. get refresh token from get
        // 2. verify refresh token
        // 3. generate new tokens
        // 4. update db returns response

        const originalRefreshToken = req.cookies.refreshToken;

        let id;
        try{
           id = JWTServices.verifyRefreshToken(originalRefreshToken)._id;
        }
        catch(e){
            const error = {
                status: 401,
                message: "unauthorized",
            }
            return next(error);

        }

        try{
           const match = RefreshToken.findOne({_id: id, token: originalRefreshToken});

           if(!match){
            const error = {
                status: 401,
                message: "Unauthorized",
            }
            return next(error);
           }
        }
        catch(e){
            return next(e);
        }

        try{
            const accessToken = JWTServices.signAccessToken({_id: id}, '30m');

            const refreshToken = JWTServices.signAccessToken({_id: id}, '60m');

            await RefreshToken.updateOne({_id: id}, {token: refreshToken});

            res.cookie('accessToken', accessToken, {
                maxAge: 1000 * 60 * 60 * 24,
                httpOnly: true
            })
            res.cookie('refreshToken', refreshToken, {
                maxAge: 1000 * 60 * 60 * 24,
                httpOnly: true
            })

        }catch(e){
            return next(e);

        }

        const user = await User.findOne({_id: id});

        const userDTO = new userDto(user);

        return res.status(200).json({user: userDTO, auth: true});



    }
}

module.exports = authController;