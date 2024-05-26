import mongoose from "mongoose";

const User = new mongoose.Schema({
    e_code: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    gender: {
        type: Boolean,
        required: true
    },
    phone: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        required: true,
    },
}, { timestamps: true })
export default mongoose.model("users", User)