const bcrypt = require('bcryptjs')
const jwt =  require('jsonwebtoken')
const User =  require('../models/User')
const keys =  require('../config/keys')
const errorHandler = require('../utils/errorHandler')

module.exports.login = async function(req, res) {
    const candidate = await User.findOne({email: req.body.email})

    if (candidate) {
        // check password of the user
        const passwordResult = bcrypt.compareSync(req.body.password, candidate.password)
        if (passwordResult) {
            // generate token, password are equal
            const token = jwt.sign({
                email: candidate.email,
                userId: candidate._id
            }, keys.jwt, {expiresIn: 60 * 60})

            res.status(200).json({
                token: `Bearer ${token}`
            })
        } else {
            // passwords are different
            res.status(401).json({
                message: 'Wrong password'
            })
        }
    } else {
        //there is no such user
        res.status(404).json({
            message: 'User with such email doesn`t exist'
        })
    }
}

module.exports.register = async function(req, res) {
    // email password
    const candidate = await User.findOne({email: req.body.email})
    
    if (candidate) {
        // User exists return error
        res.status(409).json({
            message: 'This email is already in use. Try another.'
        })
    } else {
        // Create user
        const salt = bcrypt.genSaltSync(10)
        const password = req.body.password
        const user = new User({
            email: req.body.email,
            password: bcrypt.hashSync(password, salt)
        })

        try {
            await user.save()
            res.status(201).json(user)
        } catch(e) {
            errorHandler(res, e)
        }
    }
}