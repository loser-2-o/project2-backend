const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
require('dotenv').config()

const app = express()
app.use(express.json())
app.use(cors())

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected!'))
  .catch((err) => console.log('Error:', err))

const adminSchema = new mongoose.Schema({
  username: String,
  password: String
})
const Admin = mongoose.model('Admin', adminSchema)

const submissionSchema = new mongoose.Schema({
  title: String,
  abstract: String,
  status: { type: String, default: 'pending' }
})
const Submission = mongoose.model('Submission', submissionSchema)

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ message: 'No token!' })
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.admin = decoded
    next()
  } catch {
    res.status(401).json({ message: 'Invalid token!' })
  }
}

app.post('/register', async (req, res) => {
  const { username, password } = req.body
  const hashed = await bcrypt.hash(password, 10)
  const admin = new Admin({ username, password: hashed })
  await admin.save()
  res.json({ message: 'Admin created!' })
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  const admin = await Admin.findOne({ username })
  if (!admin) return res.status(404).json({ message: 'Admin not found' })
  const isMatch = await bcrypt.compare(password, admin.password)
  if (!isMatch) return res.status(401).json({ message: 'Wrong password' })
  const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET)
  res.json({ message: 'Login successful!', token })
})

app.get('/submissions/public', async (req, res) => {
  const submissions = await Submission.find(
    { status: { $ne: 'rejected' } },
    'title status'
  )
  res.json(submissions)
})

app.post('/submissions', async (req, res) => {
  const { title, abstract } = req.body
  const submission = new Submission({ title, abstract })
  await submission.save()
  res.json({ message: 'Submitted successfully!', submission })
})

app.get('/submissions', authMiddleware, async (req, res) => {
  const submissions = await Submission.find()
  res.json(submissions)
})

app.patch('/submissions/:id', authMiddleware, async (req, res) => {
  const { status } = req.body
  if (status === 'rejected') {
    await Submission.findByIdAndDelete(req.params.id)
    return res.json({ message: 'Submission deleted!' })
  }
  const submission = await Submission.findByIdAndUpdate(
    req.params.id,
    { status },
    { new: true }
  )
  res.json({ message: 'Status updated!', submission })
})

app.listen(process.env.PORT, () => {
  console.log('Server started on port', process.env.PORT)
})