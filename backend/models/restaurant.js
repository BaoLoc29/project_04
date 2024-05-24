import mongoose from "mongoose";

const Restaurant = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    address: {
        type: String,
        required: true
    },
    open_time: {
        type: String,
        required: true
    },
    close_time: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    }

}, { timestamps: true })
export default mongoose.model("restaurant", Restaurant)