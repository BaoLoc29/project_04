import mongoose from "mongoose";

const Table = new mongoose.Schema({
    id_table: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    capacity: {
        type: Number,
        required: true
    },
    location: {
        type: String,
        required: true,
    },
    status: {
        type: String,
        required: true
    },
}, { timestamps: true })
export default mongoose.model("tables", Table)