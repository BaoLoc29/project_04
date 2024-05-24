import express from "express"
import { createMenu, editMenu } from "../controllers/menu.js"

const router = express.Router()
router.post("/createMenu", createMenu)
router.put("/:id", editMenu)
export default router