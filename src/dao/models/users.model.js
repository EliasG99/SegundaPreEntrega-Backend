import mongoose from "mongoose";

const usersCollection = 'users'
const usersSchema = new mongoose.Schema(
  {
    name: String,
    email: {
      type: String, unique: true
    },
    password: String,
    role: String
  },

  {
    strict: false,
    timestamps: {
      updatedAt: 'lastModified', createdAt: 'signupDate'
    }
  }
)

export const usersModel = mongoose.model(usersCollection, usersSchema)