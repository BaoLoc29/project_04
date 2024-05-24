import connectToDb from "./db/index.js";
import express from "express";
import route from "./routes/index.js";
import dotenv from "dotenv"
import cors from "cors"

const app = express();
dotenv.config()
app.use(express.json());
app.use(cors({
    origin: "*"
}))
app.use(route)

const PORT = 4000
connectToDb()

app.listen(PORT, () => {
    console.log(`App is listening on http://localhost:${PORT}`)
})
