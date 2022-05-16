const router = require('express').Router()
const db = require('../models')
const bcrypt =  require('bcrypt')
const jwt = require('json-web-token')

const { User } = db

router.post('/', async (req, res) => {
    let user = await User.findOne({
        where: {email: req.body.email}
    })
    
    if(!user || !await bcrypt.compare(req.body.password, user.passwordDigest)){
        res.status(404).json({
            message: `Could not find user with the provided username and password`
        })
    }else{
        const result = await jwt.encode(process.env.JWT_SECRET, {id: user.userId})
        res.status(200).json({ user, token: result.value })
    }
})

router.get('/profile', async (req, res) => {
    
    try {
        // Split Auth header into ['Bearer', 'TOKEN']:
        const [authenticationMethod, token] = req.headers.authorization.split(' ')

        // only handle 'Bearer' auth for now
        // we could add other auth strategies later:
        if(authenticationMethod === 'Bearer'){
            // decode the JWT
            const result = await jwt.decode(process.env.JWT_SECRET, token)
            // get the logged in user id from payload
            const { id } = result.value
            // find the user obj using their id:
            let user = await User.findOne({
                where: {
                    userId: id
                }
            })
            res.json(req.currentUser)

        }
    } catch {
        res.json(null)
    }
})


module.exports = router
