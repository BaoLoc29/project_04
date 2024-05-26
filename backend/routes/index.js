import express from "express";
import userRouter from "./user.js"
import menuRouter from "./menu.js"

const router = express.Router()
router.use("/user", userRouter)
router.use("/menu", menuRouter)
export default router