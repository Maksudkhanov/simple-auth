const Router = require('express')
const { check } = require('express-validator')
const router = new Router()
const controller = require('./authController')
const authMiddleware = require('./middleware/authMiddleware')
const roleMiddleware = require('./middleware/roleMiddleware')

router.post('/register', [
	check('username', 'Username can not be empty').notEmpty(),
	check('password', 'Password must be in range 4 and 10').isLength({ min: 4, max: 10 })
], controller.register)
router.post('/login', controller.login)
router.get('/users', roleMiddleware(["USER", "ADMIN"]),authMiddleware, controller.getUsers)

module.exports = router