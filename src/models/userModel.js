import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  age: Number,
  password: String,
  role: {
    type: String,
    enum: ['admin', 'usuario'],
    default: 'usuario'
  }
}, { timestamps: true });

export default mongoose.model('User', userSchema);