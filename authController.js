const Role = require('./models/Role');
const User = require('./models/User');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken')
const { secret } = require('./config')

function generateAccessToken(id, roles) {
	const payload = {
		id,
		roles
	}
	return jwt.sign(payload, secret, { expiresIn: '24h' })
}

class AuthController {
	async register(req, res) {
		try {
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				return res.status(400).json({ message: 'Register error', errors })
			}
			const { username, password } = req.body
			const candidate = await User.findOne({ username })
			if (candidate) {
				return res.status(400).json({ message: 'User with such username exists' })
			}
			const hashPassword = bcrypt.hashSync(password, 2)
			const userRole = await Role.findOne({ value: "USER" })
			const user = new User({ username, password: hashPassword, roles: [userRole.value] })
			await user.save()

			res.status(400).json({ message: 'User successfully registred' })
		} catch (error) {
			console.log(error);
			res.status(400).json({ message: 'Register error' })
		}
	}

	async login(req, res) {
		try {
			const { username, password } = req.body
			const user = await User.findOne({ username })
			if (!user) {
				return res.status(400).json({ message: 'No user with this username' })
			}
			const validPassword = bcrypt.compareSync(password, user.password)
			if (!validPassword) {
				return res.status(400).json({ message: 'Incorrect username' })
			}
			const token = generateAccessToken(user._id, user.roles)
			res.json({ token })
		} catch (error) {
			console.log(error);
			res.status(400).json({ message: 'Login error' })
		}
	}

	async getUsers(req, res) {
		try {
			const users = await User.find()
			res.json(users)
		} catch (error) {

		}
	}
}

module.exports = new AuthController()