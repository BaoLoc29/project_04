import express from "express";
import userRouter from "./user.js"
import menuRouter from "./menu.js"
import tableRouter from "./table.js"

const router = express.Router()
router.use("/user", userRouter)
router.use("/menu", menuRouter)
router.use("/table", tableRouter)
export default router