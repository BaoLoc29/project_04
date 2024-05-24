import mongoose from "mongoose"

const url = "mongodb+srv://loctranbao111:12345@cluster0.jm3fscb.mongodb.net/project_04"
const connectToDb = async () => {
    try {
        await mongoose.connect(url)
        console.log("Database connect successful")
    } catch (error) {
        console.log(error)
    }
}

export default connectToDb