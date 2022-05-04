const express = require('express')
const mongoose = require('mongoose')
const authRouter = require('./authRouter')

const PORT = process.env.PORT || 5000

const app = express()

app.use(express.json())
app.use('/auth', authRouter)

const start = (async () => {
	try {
		await mongoose.connect('mongodb+srv://admin:admin@cluster0.bwviv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority')
		app.listen(PORT, () => {
			console.log(`Server is up on port ${PORT}`);
		})
	} catch (error) {
		console.log(error);
	}
})()